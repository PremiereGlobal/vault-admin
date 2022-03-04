package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"reflect"

	VaultApi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// type AuditDevice struct {
//   Type string `json:"type"`
//   Description string `json:"description"`
//   Options map[string]interface{} `json:"options"`
// }

type AuditDeviceList map[string]VaultApi.EnableAuditOptions

func SyncAuditDevices() {

	auditDeviceList := AuditDeviceList{}

	log.Info("Syncing Audit Devices")
	GetAuditDevices(auditDeviceList)
	ConfigureAuditDevices(auditDeviceList)
	CleanupAuditDevices(auditDeviceList)
}

func GetAuditDevices(auditDeviceList AuditDeviceList) {
	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/audit_devices/")
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

			auditDeviceList[path] = m
		} else {
			log.Warn("Audit file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"/audit_devices/"+file.Name())
		}
	}
}

func ConfigureAuditDevices(auditDeviceList AuditDeviceList) {
	for mountPath, auditDevice := range auditDeviceList {

		// Check if mount is enabled
		create := false
		recreate := false
		existingDevices, _ := VaultSys.ListAudit()
		if _, ok := existingDevices[mountPath]; ok {
			if existingDevices[mountPath].Type != auditDevice.Type || !reflect.DeepEqual(existingDevices[mountPath].Options, auditDevice.Options) || existingDevices[mountPath].Description != auditDevice.Description {
				log.Info("Audit device [" + mountPath + "] exists but doesn't match configuration.  Must recreate to update.")
				if askForConfirmation("Recreate audit device ["+mountPath+"] to reconfigure [y/n]?: ", 3) {
					err := VaultSys.DisableAudit(mountPath)
					if err != nil {
						log.Fatal("Error deleting audit device ["+mountPath+"]", err)
					}
					log.Info("Audit device [" + mountPath + "] deleted")
					recreate = true
				} else {
					log.Info("Leaving [" + mountPath + "] even though it does not match configuration")
				}
			}
		} else {
			create = true
		}

		if create || recreate {
			log.Debug("Enabling audit device [" + mountPath + "]")
			err := VaultSys.EnableAuditWithOptions(mountPath, &auditDevice)
			if err != nil {
				log.Fatal("Error enabling audit device ["+mountPath+"]", err)
			}
			log.Info("Audit device [" + mountPath + "] enabled")
		}
	}
}

func CleanupAuditDevices(auditDeviceList AuditDeviceList) {

	existingDevices, _ := VaultSys.ListAudit()

	for mountPath := range existingDevices {

		if _, ok := auditDeviceList[mountPath]; ok {
			log.Debug("Audit device [" + mountPath + "] exists in configuration, no cleanup necessary")
		} else {
			auditPath := path.Join("sys/audit", mountPath)
			task := taskDelete{
				Description: fmt.Sprintf("Audit device [%s]", auditPath),
				Path:        auditPath,
			}
			taskPromptChan <- task
		}
	}
}
