package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

type SecretsEngineDatabase struct {
	Roles map[string]string
}

func ConfigureDatabaseSecretsEngine(secretsEngine SecretsEngine) {

	var secretsEngineDatabase SecretsEngineDatabase

	// Read in database configuration
	content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "db.json")
	if err != nil {
		log.Fatal("Database secrets engine config file for path ["+secretsEngine.Path+"] not found. Cannot configure engine.", err)
	}

	// Perform any substitutions
	contentstring := string(content)
	success, errMsg := performSubstitutions(&contentstring, "secrets-engines/"+secretsEngine.Name)
	if !success {
		log.Warn(errMsg)
		log.Warn("Secret substitution failed for [" + Spec.ConfigurationPath + "secrets-engines/" + secretsEngine.Path + "aws.json" + "], skipping secret engine [" + secretsEngine.Path + "]")
		return
	}

	if !isJSON(contentstring) {
		log.Fatal("Database secrets engine db.json for [" + secretsEngine.Path + "] is not a valid JSON file.")
	}

	// Get roles associated with this engine
	getDatabaseRoles(&secretsEngine, &secretsEngineDatabase)

	dbConfigPath := path.Join(secretsEngine.Path, "config/db")
	var dbConfigMap map[string]interface{}
	if err := json.Unmarshal([]byte(contentstring), &dbConfigMap); err != nil {
		log.Fatalf("Database config [%s] failed to unmarshall after secret substitution", dbConfigPath)
	}

	// Write db config
	// TODO: Add support for multiple dbs
	task := taskWrite{
		Path:        dbConfigPath,
		Description: fmt.Sprintf("Database config [%s] ", dbConfigPath),
		Data:        dbConfigMap,
	}
	wg.Add(1)
	taskChan <- task

	// Create/Update Roles
	log.Debug("Writing database roles for [" + secretsEngine.Path + "]")
	for role_name, role := range secretsEngineDatabase.Roles {

		rolePath := path.Join(secretsEngine.Path, "roles", role_name)

		var configMap map[string]interface{}
		if err := json.Unmarshal([]byte(role), &configMap); err != nil {
			log.Fatalf("Database role [%s] failed to unmarshall after secret substitution", rolePath)
		}

		task := taskWrite{
			Path:        rolePath,
			Description: fmt.Sprintf("Database role [%s] ", rolePath),
			Data:        configMap,
		}
		wg.Add(1)
		taskChan <- task
	}

	// Cleanup Roles
	cleanupDatabaseRoles(secretsEngine, secretsEngineDatabase)
}

func getDatabaseRoles(secretsEngine *SecretsEngine, secretsEngineDatabase *SecretsEngineDatabase) {

	secretsEngineDatabase.Roles = make(map[string]string)

	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "roles")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {

		success, content := getJsonFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "roles/" + file.Name())
		if success {
			filename := file.Name()
			role_name := filename[0 : len(filename)-len(filepath.Ext(filename))]
			secretsEngineDatabase.Roles[role_name] = content
		} else {
			log.Warn("Database Role file has wrong extension.  Will not be processed: ", file.Name())
		}
	}
}

func cleanupDatabaseRoles(secretsEngine SecretsEngine, secretsEngineDatabase SecretsEngineDatabase) {

	existing_roles := getSecretList(secretsEngine.Path + "roles")
	for _, role := range existing_roles {
		rolePath := secretsEngine.Path + "roles/" + role
		if _, ok := secretsEngineDatabase.Roles[role]; ok {
			log.Debug("[" + rolePath + "] exists in configuration, no cleanup necessary")
		} else {
			task := taskDelete{
				Description: fmt.Sprintf("Database role [%s]", rolePath),
				Path:        rolePath,
			}
			taskPromptChan <- task
		}
	}
}
