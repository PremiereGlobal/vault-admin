package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	VaultApi "github.com/hashicorp/vault/api"
	"io/ioutil"
)

type SecretsEngine struct {
	Name         string
	Path         string
	MountInput   VaultApi.MountInput
	EngineConfig interface{}
	JustEnabled  bool // Flagged the first time a mount gets enabled
}

type SecretsEnginesList map[string]SecretsEngine

func SyncSecretsEngines() {

	secretsEnginesList := SecretsEnginesList{}

	log.Info("Syncing Secrets Engines")
	GetSecretsEngines(secretsEnginesList)
	ConfigureSecretsEngines(secretsEnginesList)
	CleanupSecretsEngines(secretsEnginesList)
}

func GetSecretsEngines(secretsEnginesList SecretsEnginesList) {
	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/secrets-engines/")
	if err != nil {
		log.Warn("No secrets engines found: ", err)
	}

	for _, file := range files {
		if file.IsDir() {
			var se SecretsEngine
			se.Name = file.Name()
			se.Path = file.Name() + "/"

			// Identity store doesn't have any configure as it is enabled by default
			if se.Name != "identity" {

				content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/secrets-engines/" + file.Name() + "/config.json")
				if err != nil {
					log.Fatal("Config file for secret engine ["+se.Path+"] not found. ", err)
				}

				if !isJSON(string(content)) {
					log.Fatal("Secret engine config.json for [" + se.Path + "] is not a valid JSON file.")
				}

				err = json.Unmarshal([]byte(content), &se.MountInput)
				if err != nil {
					log.Fatal("Error parsing secret backend config for [" + se.Path + "]")
				}
			}

			secretsEnginesList[se.Path] = se
		}
	}
}

func ConfigureSecretsEngines(secretsEnginesList SecretsEnginesList) {
	for _, secretsEngine := range secretsEnginesList {

		// Check if mount is enabled
		existing_mounts, _ := VaultSys.ListMounts()
		if _, ok := existing_mounts[secretsEngine.Path]; ok {

			// We don't need to do any setup for identity backend
			if secretsEngine.Path != "identity/" {
				if existing_mounts[secretsEngine.Path].Type != secretsEngine.MountInput.Type {
					log.Fatal("Secrets engine path ["+secretsEngine.Path+"] exists but doesn't match type; ", existing_mounts[secretsEngine.Path].Type, "!=", secretsEngine.MountInput.Type)
				}
				log.Debug("Secrets engine path [" + secretsEngine.Path + "] already enabled and type matches, tuning for any updates")

				// Update the MountConfigInput description to match the MountInput description
				// This is needed because of the way creating new mounts differs from existing ones?
				secretsEngine.MountInput.Config.Description = &secretsEngine.MountInput.Description

				err := VaultSys.TuneMount(secretsEngine.Path, secretsEngine.MountInput.Config)
				if err != nil {
					log.Fatal("Error tuning secrets engine path ["+secretsEngine.Path+"]", err)
				}
			}
		} else {
			log.Debug("Secrets engine path [" + secretsEngine.Path + "] is not enabled, enabling")
			err := VaultSys.Mount(secretsEngine.Path, &secretsEngine.MountInput)
			if err != nil {
				log.Fatal("Error mounting secret type ["+secretsEngine.MountInput.Type+"] mounted at ["+secretsEngine.Path+"]; ", err)
			}
			log.Info("Secrets engine type [" + secretsEngine.MountInput.Type + "] enabled at [" + secretsEngine.Path + "]")
			secretsEngine.JustEnabled = true
		}

		if secretsEngine.Path == "identity/" {
			log.Info("Configuring Identity backend ", secretsEngine.Path)
			configureIdentitySecretsEngine(secretsEngine)
		} else if secretsEngine.MountInput.Type == "aws" {
			log.Info("Configuring AWS backend ", secretsEngine.Path)
			ConfigureAwsSecretsEngine(secretsEngine)
		} else if secretsEngine.MountInput.Type == "database" {
			log.Info("Configuring database backend ", secretsEngine.Path)
			ConfigureDatabaseSecretsEngine(secretsEngine)
		} else {
			log.Warn("Secrets engine types other than [aws] and [database] not currently configurable, please open PR!")
		}
	}
}

func CleanupSecretsEngines(secretsEnginesList SecretsEnginesList) {
	existing_mounts, _ := VaultSys.ListMounts()

	for path, mountOutput := range existing_mounts {

		// Ignore default mounts
		// generic = old kv store
		if !(mountOutput.Type == "system" || mountOutput.Type == "cubbyhole" || mountOutput.Type == "identity" || mountOutput.Type == "kv" || mountOutput.Type == "generic") {
			if _, ok := secretsEnginesList[path]; ok {
				log.Debug("Secrets engine [" + path + "] exists in configuration, no cleanup necessary")
			} else {
				log.Debug("Secrets engine [" + path + "] does not exist in configuration, prompting to delete")
				if askForConfirmation("Secrets engine ["+path+"] does not exist in configuration. Delete [y/n]?: ", 3) {
					err := VaultSys.Unmount(path)
					if err != nil {
						log.Fatal("Error deleting mount ", path, err)
					}
					log.Info("Secrets engine [" + path + "] deleted")
				} else {
					log.Info("Leaving secrets engine [" + path + "] even though it is not in config")
				}
			}
		}
	}
}
