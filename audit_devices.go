package main

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"reflect"

	VaultApi "github.com/hashicorp/vault/api"
)

type syncAuditDevicesTask struct {
	auditDeviceList map[string]VaultApi.EnableAuditOptions
}

type configureAuditDeviceTask struct {
	mountPath   string
	auditDevice VaultApi.EnableAuditOptions
}

type cleanupAuditDevicesTask struct {
	auditDeviceList map[string]VaultApi.EnableAuditOptions
}

type recreateAuditDeviceTask struct {
	mountPath   string
	auditDevice VaultApi.EnableAuditOptions
}

func (s syncAuditDevicesTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	log.Info("Syncing Audit Devices")
	s.auditDeviceList = make(map[string]VaultApi.EnableAuditOptions)
	s.Load()

	// Add to devices to channel to be processed
	for mountPath, auditDevice := range s.auditDeviceList {
		configureAuditDeviceTask := configureAuditDeviceTask{
			mountPath:   mountPath,
			auditDevice: auditDevice,
		}
		wg.Add(1)
		taskChan <- configureAuditDeviceTask
	}

	// Add cleanup task
	cleanupAuditDevicesTask := cleanupAuditDevicesTask{
		auditDeviceList: s.auditDeviceList,
	}
	taskPromptChan <- cleanupAuditDevicesTask

	return true
}

func (s syncAuditDevicesTask) Load() {
	files, err := ioutil.ReadDir(filepath.Join(Spec.ConfigurationPath, "audit_devices"))
	if err != nil {
		log.Warn("No audit devices found: ", err)
		return
	}

	for _, file := range files {

		if checkExt(file.Name(), ".json") {
			content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/audit_devices/" + file.Name())
			if err != nil {
				log.Fatal(err)
			}

			if !isJSON(string(content)) {
				log.Fatal("Audit device configuration not valid JSON: ", file.Name())
			}

			var m VaultApi.EnableAuditOptions

			// Use the filename as the mount path
			filename := file.Name()
			path := filename[0:len(filename)-len(filepath.Ext(filename))] + "/"
			err = json.Unmarshal([]byte(content), &m)
			if err != nil {
				log.Fatal("Error parsing audit device configuration: ", file.Name(), " ", err)
			}

			s.auditDeviceList[path] = m
		} else {
			log.Warn("Audit file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"/audit_devices/"+file.Name())
		}
	}
}

// func (s syncAuditDevicesTask) ConfigureAuditDevices(auditDeviceList AuditDeviceList) {
func (c configureAuditDeviceTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	existingDevices, _ := VaultSys.ListAudit()
	if _, ok := existingDevices[c.mountPath]; ok {
		if existingDevices[c.mountPath].Type != c.auditDevice.Type || !reflect.DeepEqual(existingDevices[c.mountPath].Options, c.auditDevice.Options) || existingDevices[c.mountPath].Description != c.auditDevice.Description {
			recreateAuditDeviceTask := recreateAuditDeviceTask{
				mountPath:   c.mountPath,
				auditDevice: c.auditDevice,
			}
			taskPromptChan <- recreateAuditDeviceTask
		} else {
			log.Infof("Audit device %s already in sync", c.mountPath)
		}
	} else {
		createAuditDevice(c.mountPath, c.auditDevice)
	}

	return true
}

func createAuditDevice(mountPath string, auditDevice VaultApi.EnableAuditOptions) {
	log.Debug("Enabling audit device [" + mountPath + "]")
	err := VaultSys.EnableAuditWithOptions(mountPath, &auditDevice)
	if err != nil {
		log.Fatal("Error enabling audit device ["+mountPath+"]", err)
	}
	log.Info("Audit device [" + mountPath + "] enabled")
}

func (r recreateAuditDeviceTask) run(workerNum int) bool {

	log.Info("Audit device [" + r.mountPath + "] exists but doesn't match configuration.  Must recreate to update.")
	if askForConfirmation("Recreate audit device [" + r.mountPath + "] to reconfigure") {
		err := VaultSys.DisableAudit(r.mountPath)
		if err != nil {
			log.Fatal("Error deleting audit device ["+r.mountPath+"]", err)
		}
		log.Info("Audit device [" + r.mountPath + "] deleted")
		createAuditDevice(r.mountPath, r.auditDevice)
	} else {
		log.Info("Leaving [" + r.mountPath + "] even though it does not match configuration")
	}

	return true
}

func (c cleanupAuditDevicesTask) run(workerNum int) bool {

	existingDevices, _ := VaultSys.ListAudit()

	for mountPath, _ := range existingDevices {

		if _, ok := c.auditDeviceList[mountPath]; ok {
			log.Debug("Audit device [" + mountPath + "] exists in configuration, no cleanup necessary")
		} else {
			log.Info("Audit device [" + mountPath + "] does not exist in configuration, prompting to delete")
			if askForConfirmation("Delete audit device [" + mountPath + "]?") {
				err := VaultSys.DisableAudit(mountPath)
				if err != nil {
					log.Fatal("Error deleting audit device ["+mountPath+"]", err)
				}
				log.Info("Audit device [" + mountPath + "] deleted")
			} else {
				log.Info("Leaving [" + mountPath + "] even though it does not match configuration")
			}
		}
	}

	return true
}
