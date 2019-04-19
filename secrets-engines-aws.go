package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	"io/ioutil"
	"path/filepath"
	"time"
)

type SecretsEngineAWS struct {
	RootConfig  AwsRootConfig  `json:"root_config"`
	ConfigLease AwsConfigLease `json:"config_lease"`
	Roles       map[string]awsRoleEntry
}

type AwsRootConfig struct {
	AccessKey   string `json:"access_key"`
	SecretKey   string `json:"secret_key"`
	IAMEndpoint string `json:"iam_endpoint"`
	STSEndpoint string `json:"sts_endpoint"`
	Region      string `json:"region"`
	MaxRetries  int    `json:"max_retries"`
}

type AwsConfigLease struct {
	Lease    string `json:"lease"`
	LeaseMax string `json:"lease_max"`
}

type awsRoleEntry struct {
	CredentialType string        `json:"credential_type"`           // Entries must all be in the set of ("iam_user", "assumed_role", "federation_token")
	PolicyArns     []string      `json:"policy_arns"`               // ARNs of managed policies to attach to an IAM user
	RoleArns       []string      `json:"role_arns"`                 // ARNs of roles to assume for AssumedRole credentials
	PolicyDocument string        `json:"policy_document"`           // JSON-serialized inline policy to attach to IAM users and/or to specify as the Policy parameter in AssumeRole calls
	RawPolicy      interface{}   `json:"raw_policy,omitempty"`      // Custom field to allow policy to be entered as json as opposed to having to escape it
	DefaultSTSTTL  time.Duration `json:"default_sts_ttl,omitempty"` // Default TTL for STS credentials
	MaxSTSTTL      time.Duration `json:"max_sts_ttl,omitempty"`     // Max allowed TTL for STS credentials
}

func ConfigureAwsSecretsEngine(secretsEngine SecretsEngine) {

	var secretsEngineAWS SecretsEngineAWS

	// Read in AWS root configuration
	content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "aws.json")
	if err != nil {
		log.Fatal("AWS secrets engine config file for path ["+secretsEngine.Path+"] not found. Cannot configure engine.", err)
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
		log.Fatal("AWS secrets engine aws.json for [" + secretsEngine.Path + "] is not a valid JSON file.")
	}

	err = json.Unmarshal([]byte(contentstring), &secretsEngineAWS)
	if err != nil {
		log.Fatal("Error parsing secret engine config for ["+secretsEngine.Path+"]", err)
	}

	// Get roles associated with this engine
	getAwsRoles(&secretsEngine, &secretsEngineAWS)

	// Write root config
	log.Debug("Writing root config for [" + secretsEngine.Path + "]")
	err = writeStructToVault(secretsEngine.Path+"/config/root", secretsEngineAWS.RootConfig)
	if err != nil {
		log.Fatal("Error writing root config for ["+secretsEngine.Path+"]", err)
	}

	// Write config lease
	log.Debug("Writing config lease for [" + secretsEngine.Path + "]")
	err = writeStructToVault(secretsEngine.Path+"/config/lease", secretsEngineAWS.ConfigLease)
	if err != nil {
		log.Fatal("Error writing config lease for ["+secretsEngine.Path+"]", err)
	}

	// Create/Update Roles
	log.Debug("Writing AWS roles for [" + secretsEngine.Path + "]")
	for role_name, role := range secretsEngineAWS.Roles {
		log.Debug("Writing AWS role [" + role_name + "] to [" + secretsEngine.Path + "]")
		err = writeStructToVault(secretsEngine.Path+"roles/"+role_name, role)
		if err != nil {
			log.Fatal("Error creating/updating role ["+role_name+"] at ["+secretsEngine.Path+"]", err)
		}
	}

	// Cleanup Roles
	cleanupAwsRoles(secretsEngine, secretsEngineAWS)
}

func getAwsRoles(secretsEngine *SecretsEngine, secretsEngineAWS *SecretsEngineAWS) {

	secretsEngineAWS.Roles = make(map[string]awsRoleEntry)

	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "roles")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {

		success, content := getJsonFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "roles/" + file.Name())
		if success {
			var r awsRoleEntry

			filename := file.Name()
			role_name := filename[0 : len(filename)-len(filepath.Ext(filename))]
			err = json.Unmarshal([]byte(content), &r)
			if err != nil {
				log.Fatal("Error parsing role policy  ["+secretsEngine.Path+"roles/"+role_name+"]", err)
			}

			// Marshal the raw policy document to a string
			if r.RawPolicy != nil {
				raw_policy, err := json.Marshal(r.RawPolicy)
				if err != nil {
					log.Fatal("Error parsing raw policy statement in "+file.Name()+" ", err)
				}
				r.PolicyDocument = string(raw_policy)
				r.RawPolicy = nil
			}

			secretsEngineAWS.Roles[role_name] = r

		} else {
			log.Warn("AWS Role file has wrong extension.  Will not be processed: ", file.Name())
		}
	}
}

func cleanupAwsRoles(secretsEngine SecretsEngine, secretsEngineAWS SecretsEngineAWS) {

	success, existing_roles := getSecretList(secretsEngine.Path + "roles")
	if success {
		for _, role := range existing_roles {
			rolePath := secretsEngine.Path + "roles/" + role
			if _, ok := secretsEngineAWS.Roles[role]; ok {
				log.Debug("[" + rolePath + "] exists in configuration, no cleanup necessary")
			} else {
				log.Debug("[" + rolePath + "] does not exist in configuration, prompting to delete")
				if askForConfirmation("Role ["+rolePath+"] does not exist in configuration.  Delete [y/n]?: ", 3) {
					_, err := Vault.Delete(rolePath)
					if err != nil {
						log.Fatal("Error deleting role ["+rolePath+"]", err)
					}
					log.Info("[" + rolePath + "] deleted")
				} else {
					log.Info("Leaving [" + rolePath + "] even though it is not in configuration")
				}
			}
		}
	}
}
