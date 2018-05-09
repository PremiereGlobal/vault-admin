package main

import (
  // "fmt"
  // "reflect"
  "io/ioutil"
  "path/filepath"
  log "github.com/Sirupsen/logrus"
)

type SecretsEngineDatabase struct {
  Roles map[string]string
}

func ConfigureDatabaseSecretsEngine(secretsEngine SecretsEngine) {

  var secretsEngineDatabase SecretsEngineDatabase

  // Read in database configuration
  content, err := ioutil.ReadFile(Spec.ConfigurationPath+"/secrets-engines/"+secretsEngine.Path+"db.json")
  if err != nil {
    log.Fatal("Database secrets engine config file for path [" + secretsEngine.Path + "] not found. Cannot configure engine.", err)
  }

  // Perform any substitutions
  contentstring := string(content)
  success, errMsg := performSubstitutions(&contentstring, "secrets-engines/"+secretsEngine.Name)
  if(!success) {
    log.Warn(errMsg)
    log.Warn("Secret substitution failed for [" + Spec.ConfigurationPath+"secrets-engines/"+secretsEngine.Path+"aws.json" + "], skipping secret engine [" + secretsEngine.Path + "]")
    return
  }

  if (!isJSON(contentstring)) {
    log.Fatal("Database secrets engine db.json for [" + secretsEngine.Path + "] is not a valid JSON file.")
  }

  // Get roles associated with this engine
  getDatabaseRoles(&secretsEngine, &secretsEngineDatabase)

  // Write db config
  // TODO: Add support for multiple dbs
  log.Debug("Writing db config for [" + secretsEngine.Path + "/db]")
  err = writeStringToVault(secretsEngine.Path+"/config/db", contentstring)
  if err != nil {
    log.Fatal("Error writing config for [" + secretsEngine.Path + "/db]", err)
  }

  // Create/Update Roles
  log.Debug("Writing roles for [" + secretsEngine.Path + "]")
  for role_name, role := range secretsEngineDatabase.Roles {
    log.Debug("Writting role [" + role_name + "] to [" + secretsEngine.Path + "]")
    err = writeStringToVault(secretsEngine.Path+"roles/"+role_name, role)
    if err != nil {
  		log.Fatal("Error creating/updating role [" + role_name + "] at [" + secretsEngine.Path + "]", err)
  	}
  }

  // Cleanup Roles
  cleanupDatabaseRoles(secretsEngine, secretsEngineDatabase)
}

func getDatabaseRoles(secretsEngine *SecretsEngine, secretsEngineDatabase *SecretsEngineDatabase) {

  secretsEngineDatabase.Roles = make(map[string]string)

  files, err := ioutil.ReadDir(Spec.ConfigurationPath+"/secrets-engines/"+secretsEngine.Path+"roles")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {

    success, content := getJsonFile(Spec.ConfigurationPath+"/secrets-engines/"+secretsEngine.Path+"roles/"+file.Name())
    if success {
      filename := file.Name()
      role_name := filename[0:len(filename)-len(filepath.Ext(filename))]
      secretsEngineDatabase.Roles[role_name] = content
    } else {
      log.Warn("Database Role file has wrong extension.  Will not be processed: ", file.Name())
    }
	}
}

func cleanupDatabaseRoles(secretsEngine SecretsEngine, secretsEngineDatabase SecretsEngineDatabase) {

  success, existing_roles := getSecretList(secretsEngine.Path + "roles")
  if success {
    for _, role := range existing_roles {
      rolePath := secretsEngine.Path + "roles/" + role
      if _, ok := secretsEngineDatabase.Roles[role]; ok {
        log.Debug("[" + rolePath + "] exists in configuration, no cleanup necessary")
      } else {
        log.Debug("[" + rolePath + "] does not exist in configuration, prompting to delete")
        if( askForConfirmation("Role [" + rolePath + "] does not exist in configuration.  Delete [y/n]?: ") ) {
          _, err := Vault.Delete(rolePath)
          if err != nil {
        		log.Fatal("Error deleting role [" + rolePath + "]", err)
        	}
          log.Info("[" + rolePath + "] deleted")
        } else {
          log.Info("Leaving [" + rolePath + "] even though it is not in configuration")
        }
      }
    }
  }
}
