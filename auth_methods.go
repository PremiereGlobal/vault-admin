package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	VaultApi "github.com/hashicorp/vault/api"
	"io/ioutil"
	"path/filepath"
)

type authMethod struct {
	Path             string                     `json:"path"`
	AuthOptions      VaultApi.EnableAuthOptions `json:"auth_options"`
	Config           map[string]interface{}     `json:"config"`
	AdditionalConfig interface{}                `json:"additional_config"`
}

type authMethodList map[string]authMethod

func SyncAuthMethods() {

	authMethodList := authMethodList{}

	log.Info("Syncing Auth Methods")
	getAuthMethods(authMethodList)
	configureAuthMethods(authMethodList)
	cleanupAuthMethods(authMethodList)
}

func getAuthMethods(authMethodList authMethodList) {
	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/auth_methods/")
	if err != nil {
		log.Warn("No auth methods found: ", err)
	}

	for _, file := range files {

		if checkExt(file.Name(), ".json") {
			content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/auth_methods/" + file.Name())
			if err != nil {
				log.Fatal(err)
			}

			if !isJSON(string(content)) {
				log.Fatal("Auth method configuration not valid JSON: ", file.Name())
			}

			var m authMethod

			// Use the filename as the mount path
			filename := file.Name()
			m.Path = filename[0:len(filename)-len(filepath.Ext(filename))] + "/"
			err = json.Unmarshal([]byte(content), &m)
			if err != nil {
				log.Fatal("Error parsing auth method configuration: ", file.Name(), " ", err)
			}

			authMethodList[m.Path] = m
		} else {
			log.Warn("Auth file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"/auth_methods/"+file.Name())
		}
	}
}

func configureAuthMethods(authMethodList authMethodList) {
	for _, mount := range authMethodList {

		// Check if mount is enabled
		existing_mounts, _ := VaultSys.ListAuth()
		if _, ok := existing_mounts[mount.Path]; ok {
			if existing_mounts[mount.Path].Type != mount.AuthOptions.Type {
				log.Fatal("Auth mount path  "+mount.Path+" exists but doesn't match type: ", existing_mounts[mount.Path].Type, "!=", mount.AuthOptions.Type)
			}
			log.Debug("Auth mount path " + mount.Path + " already enabled and type matches, tuning for any updates")

			var mc VaultApi.MountConfigInput
			mc.DefaultLeaseTTL = mount.AuthOptions.Config.DefaultLeaseTTL
			mc.MaxLeaseTTL = mount.AuthOptions.Config.MaxLeaseTTL
			mc.ListingVisibility = mount.AuthOptions.Config.ListingVisibility
			mc.Description = &mount.AuthOptions.Description
			err := VaultSys.TuneMount("/auth/"+mount.Path, mc)
			if err != nil {
				log.Fatal("Error tuning mount: ", mount.Path, " ", err)
			}
		} else {
			log.Debug("Auth mount path " + mount.Path + " is not enabled, enabling")
			err := VaultSys.EnableAuthWithOptions(mount.Path, &mount.AuthOptions)
			if err != nil {
				log.Fatal("Error enabling mount: ", mount.Path, " ", mount.AuthOptions.Type, " ", err)
			}
			log.Info("Auth enabled: ", mount.Path, " ", mount.AuthOptions.Type)
		}

		// Write the auth configuration (if set)
		if mount.Config != nil {
			log.Debug("Writing auth config for ", mount.Path)
			_, err := Vault.Write("/auth/"+mount.Path+"config", mount.Config)
			if err != nil {
				log.Fatal("Error writing LDAP config for "+mount.Path+" ", err)
			}
		}

		if mount.AuthOptions.Type == "userpass" {
			log.Info("Running additional configuration for ", mount.Path)
			configureUserpassAuth(mount)
		} else if mount.AuthOptions.Type == "ldap" {
			log.Info("Running additional configuration for ", mount.Path)
			configureLDAPAuth(mount)
		} else {
			log.Warn("Auth types other than LDAP not currently configurable, please open PR!")
		}

	}
}

func cleanupAuthMethods(authMethodList authMethodList) {
	existing_mounts, _ := VaultSys.ListAuth()

	for path, mount := range existing_mounts {

		// Ignore default token auth mount
		if !(path == "token/" && mount.Type == "token") {
			if _, ok := authMethodList[path]; ok {
				log.Debug(path + " exists in configuration, no cleanup necessary")
			} else {
				log.Info(path + " does not exist in configuration, prompting to delete")
				if askForConfirmation("Delete auth mount "+path+" [y/n]?: ", 3) {
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
}
