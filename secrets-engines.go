package main

import (
	"encoding/json"
	"io/ioutil"

	VaultApi "github.com/hashicorp/vault/api"
)

type syncSecretsEnginesTask struct {
	secretsEnginesList map[string]SecretsEngine
}

type configureSecretsEngineTask struct {
	secretsEngine SecretsEngine
}

type cleanupSecretsEnginesTask struct {
	secretsEnginesList map[string]SecretsEngine
}

// type syncSecretsEngines struct {}

type SecretsEngine struct {
	Name         string
	Path         string
	MountInput   VaultApi.MountInput
	EngineConfig interface{}
	JustEnabled  bool // Flagged the first time a mount gets enabled
}

func (s syncSecretsEnginesTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	log.Info("Syncing Secrets Engines")
	s.secretsEnginesList = make(map[string]SecretsEngine)
	s.Load()

	for _, secretsEngine := range s.secretsEnginesList {
		configureSecretsEngineTask := configureSecretsEngineTask{
			secretsEngine: secretsEngine,
		}
		wg.Add(1)
		taskChan <- configureSecretsEngineTask
	}

	// Add cleanup task
	cleanupSecretsEnginesTask := cleanupSecretsEnginesTask{
		secretsEnginesList: s.secretsEnginesList,
	}
	taskPromptChan <- cleanupSecretsEnginesTask

	return true
}

func (s syncSecretsEnginesTask) Load() {
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

			s.secretsEnginesList[se.Path] = se
		}
	}
}

func (c configureSecretsEngineTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	// Check if mount is enabled
	existing_mounts, _ := VaultSys.ListMounts()
	if _, ok := existing_mounts[c.secretsEngine.Path]; ok {

		// We don't need to do any setup for identity backend
		if c.secretsEngine.Path != "identity/" {
			if existing_mounts[c.secretsEngine.Path].Type != c.secretsEngine.MountInput.Type {
				log.Fatal("Secrets engine path ["+c.secretsEngine.Path+"] exists but doesn't match type; ", existing_mounts[c.secretsEngine.Path].Type, "!=", c.secretsEngine.MountInput.Type)
			}
			log.Debug("Secrets engine path [" + c.secretsEngine.Path + "] already enabled and type matches, tuning for any updates")

			// Update the MountConfigInput description to match the MountInput description
			// This is needed because of the way creating new mounts differs from existing ones?
			c.secretsEngine.MountInput.Config.Description = &c.secretsEngine.MountInput.Description

			err := VaultSys.TuneMount(c.secretsEngine.Path, c.secretsEngine.MountInput.Config)
			if err != nil {
				log.Fatal("Error tuning secrets engine path ["+c.secretsEngine.Path+"]", err)
			}
		}
	} else {
		log.Debug("Secrets engine path [" + c.secretsEngine.Path + "] is not enabled, enabling")
		err := VaultSys.Mount(c.secretsEngine.Path, &c.secretsEngine.MountInput)
		if err != nil {
			log.Fatal("Error mounting secret type ["+c.secretsEngine.MountInput.Type+"] mounted at ["+c.secretsEngine.Path+"]; ", err)
		}
		log.Info("Secrets engine type [" + c.secretsEngine.MountInput.Type + "] enabled at [" + c.secretsEngine.Path + "]")
		c.secretsEngine.JustEnabled = true
	}

	if c.secretsEngine.Path == "identity/" {
		log.Info("Configuring Identity backend ", c.secretsEngine.Path)
		configureIdentitySecretsEngine(c.secretsEngine)
	} else if c.secretsEngine.MountInput.Type == "aws" {
		log.Info("Configuring AWS backend ", c.secretsEngine.Path)
		ConfigureAwsSecretsEngine(c.secretsEngine)
	} else if c.secretsEngine.MountInput.Type == "database" {
		log.Info("Configuring database backend ", c.secretsEngine.Path)
		ConfigureDatabaseSecretsEngine(c.secretsEngine)
	} else {
		log.Warn("Secrets engine types other than [aws] and [database] not currently configurable, please open PR!")
	}

	return true
}

func (c cleanupSecretsEnginesTask) run(workerNum int) bool {
	existing_mounts, _ := VaultSys.ListMounts()

	for path, mountOutput := range existing_mounts {

		// Ignore default mounts
		// generic = old kv store
		if !(mountOutput.Type == "system" || mountOutput.Type == "cubbyhole" || mountOutput.Type == "identity" || mountOutput.Type == "kv" || mountOutput.Type == "generic") {
			if _, ok := c.secretsEnginesList[path]; ok {
				log.Debug("Secrets engine [" + path + "] exists in configuration, no cleanup necessary")
			} else {
				log.Debug("Secrets engine [" + path + "] does not exist in configuration, prompting to delete")
				if askForConfirmation("Secrets engine [" + path + "] does not exist in configuration. Delete?") {
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

	return true
}
