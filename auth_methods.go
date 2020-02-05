package main

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"

	VaultApi "github.com/hashicorp/vault/api"
)

type syncAuthMethodsTask struct {
	authMethodList map[string]authMethod
}

type configureAuthMethodTask struct {
	mount authMethod
}

type cleanupAuthMethodsTask struct {
	authMethodList map[string]authMethod
}

type authMethod struct {
	Name             string
	Path             string                     `json:"path"`
	AuthOptions      VaultApi.EnableAuthOptions `json:"auth_options"`
	Config           map[string]interface{}     `json:"config"`
	AdditionalConfig interface{}                `json:"additional_config"`
}

// type authMethodList map[string]authMethod

func (s syncAuthMethodsTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	log.Info("Syncing Auth Methods")
	s.authMethodList = make(map[string]authMethod)
	s.Load()

	for _, mount := range s.authMethodList {
		configureAuthMethodTask := configureAuthMethodTask{
			mount: mount,
		}
		wg.Add(1)
		taskChan <- configureAuthMethodTask
	}

	cleanupAuthMethodsTask := cleanupAuthMethodsTask{
		authMethodList: s.authMethodList,
	}
	taskPromptChan <- cleanupAuthMethodsTask

	return true
}

func (s syncAuthMethodsTask) Load() {
	authMethodPath := filepath.Join(Spec.ConfigurationPath, "auth_methods")
	files, err := ioutil.ReadDir(authMethodPath)
	if err != nil {
		log.Warn("No auth methods found: ", err)
	}

	for _, file := range files {

		authFilePath := filepath.Join(authMethodPath, file.Name())

		if checkExt(authFilePath, ".json") {
			content, err := ioutil.ReadFile(authFilePath)
			if err != nil {
				log.Fatal(err)
			}

			if !isJSON(string(content)) {
				log.Fatal("Auth method configuration not valid JSON: ", authFilePath)
			}

			var m authMethod

			// Use the filename as the mount path
			filename := file.Name()
			m.Name = filename[0 : len(filename)-len(filepath.Ext(filename))]
			m.Path = m.Name + "/"
			err = json.Unmarshal([]byte(content), &m)
			if err != nil {
				log.Fatalf("Error parsing auth method configuration %s: %v", authFilePath, err)
			}

			s.authMethodList[m.Path] = m
		} else {
			log.Warnf("Auth file %s has wrong extension.  Will not be processed.", authFilePath)
		}
	}
}

func (c configureAuthMethodTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	// Check if mount is enabled
	existing_mounts, _ := VaultSys.ListAuth()
	if _, ok := existing_mounts[c.mount.Path]; ok {
		if existing_mounts[c.mount.Path].Type != c.mount.AuthOptions.Type {
			log.Fatal("Auth mount path  "+c.mount.Path+" exists but doesn't match type: ", existing_mounts[c.mount.Path].Type, "!=", c.mount.AuthOptions.Type)
		}
		log.Debug("Auth mount path " + c.mount.Path + " already enabled and type matches, tuning for any updates")

		var mc VaultApi.MountConfigInput
		mc.DefaultLeaseTTL = c.mount.AuthOptions.Config.DefaultLeaseTTL
		mc.MaxLeaseTTL = c.mount.AuthOptions.Config.MaxLeaseTTL
		mc.ListingVisibility = c.mount.AuthOptions.Config.ListingVisibility
		mc.Description = &c.mount.AuthOptions.Description
		err := VaultSys.TuneMount("/auth/"+c.mount.Path, mc)
		if err != nil {
			log.Fatal("Error tuning mount: ", c.mount.Path, " ", err)
		}
	} else {
		log.Debug("Auth mount path " + c.mount.Path + " is not enabled, enabling")
		err := VaultSys.EnableAuthWithOptions(c.mount.Path, &c.mount.AuthOptions)
		if err != nil {
			log.Fatal("Error enabling mount: ", c.mount.Path, " ", c.mount.AuthOptions.Type, " ", err)
		}
		log.Info("Auth enabled: ", c.mount.Path, " ", c.mount.AuthOptions.Type)
	}

	// Write the auth configuration (if set)
	if c.mount.Config != nil {

		// Here we transform to json in order to do string substitution
		jsondata, err := json.Marshal(c.mount.Config)
		if err != nil {
			log.Fatal(err)
		}
		contentstring := string(jsondata)
		success, errMsg := performSubstitutions(&contentstring, "auth/"+c.mount.Name)
		if !success {
			log.Warn(errMsg)
			log.Warn("Secret substitution failed for [" + c.mount.Path + "], skipping auth method configuration")
			return false
		} else {
			if !isJSON(contentstring) {
				log.Fatal("Auth engine [" + c.mount.Path + "] is not a valid JSON after secret substitution")
			}
			log.Debug("Writing auth config for ", c.mount.Path)
			err = writeStringToVault("/auth/"+c.mount.Path+"config", contentstring)
			if err != nil {
				log.Fatal("Error writing LDAP config for "+c.mount.Path+" ", err)
			}
		}
	}

	if c.mount.AuthOptions.Type == "userpass" {

		configureUserpassAuth(c.mount)
	} else if c.mount.AuthOptions.Type == "ldap" {
		// log.Info("Running additional configuration for ", c.mount.Path)
		configureLDAPAuth(c.mount)
	} else {
		log.Warn("Auth types other than LDAP not currently configurable, please open PR!")
	}

	log.Infof("Auth Method: %s configured", c.mount.Path)

	return true
}

func (c cleanupAuthMethodsTask) run(workerNum int) bool {
	existing_mounts, _ := VaultSys.ListAuth()

	for path, mount := range existing_mounts {

		// Ignore default token auth mount
		if !(path == "token/" && mount.Type == "token") {
			if _, ok := c.authMethodList[path]; ok {
				log.Debug(path + " exists in configuration, no cleanup necessary")
			} else {
				log.Info(path + " does not exist in configuration, prompting to delete")
				if askForConfirmation("Delete auth mount " + path) {
					err := VaultSys.DisableAuth(path)
					if err != nil {
						log.Fatal("Error deleting auth mount ", path, err)
					}
					log.Info(path + " auth mount deleted")
				} else {
					log.Info("Leaving " + path + " even though it is not in config")
				}
			}
		}
	}

	return true
}
