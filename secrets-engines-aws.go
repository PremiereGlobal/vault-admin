package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

type SecretsEngineAWS struct {
	RootConfig               AwsRootConfig  `json:"root_config"`
	OverwriteRootCredentials bool           `json:"overwrite_root_config"`
	ConfigLease              AwsConfigLease `json:"config_lease"`
	Roles                    map[string]awsRoleEntry
}

type AwsRootConfig struct {
	AccessKey   string `json:"access_key,omitempty"`
	SecretKey   string `json:"secret_key,omitempty"`
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
	CredentialType string        `json:"credential_type",yaml:"credential_type"`                     // Entries must all be in the set of ("iam_user", "assumed_role", "federation_token")
	PolicyArns     []string      `json:"policy_arns",yaml:"policy_arns"`                             // ARNs of managed policies to attach to an IAM user
	RoleArns       []string      `json:"role_arns",yaml:"role_arns"`                                 // ARNs of roles to assume for AssumedRole credentials
	PolicyDocument string        `json:"policy_document",yaml:"policy_document"`                     // JSON-serialized inline policy to attach to IAM users and/or to specify as the Policy parameter in AssumeRole calls
	RawPolicy      interface{}   `json:"raw_policy,omitempty",yaml:"raw_policy,omitempty"`           // Custom field to allow policy to be entered as json as opposed to having to escape it
	DefaultSTSTTL  time.Duration `json:"default_sts_ttl,omitempty",yaml:"default_sts_ttl,omitempty"` // Default TTL for STS credentials
	MaxSTSTTL      time.Duration `json:"max_sts_ttl,omitempty",yaml:"max_sts_ttl,omitempty"`         // Max allowed TTL for STS credentials
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
	// Only write the root config if this is the first time setting up the engine
	// or if the overwrite_root_config flag is set
	if secretsEngine.JustEnabled || secretsEngineAWS.OverwriteRootCredentials {
		log.Debug("Writing root config for [" + secretsEngine.Path + "]. JustEnabled=" + strconv.FormatBool(secretsEngine.JustEnabled) + ", OverwriteRootCredentials=" + strconv.FormatBool(secretsEngineAWS.OverwriteRootCredentials))

		rootConfigPath := path.Join(secretsEngine.Path, "config/root")
		task := taskWrite{
			Path:        rootConfigPath,
			Description: fmt.Sprintf("AWS root config [%s]", rootConfigPath),
			Data:        structToMap(secretsEngineAWS.RootConfig),
		}
		wg.Add(1)
		taskChan <- task

	} else {
		log.Debug("Root config exists for [" + secretsEngine.Path + "], skipping...")
	}

	// Write config lease
	configLeasePath := path.Join(secretsEngine.Path, "config/lease")
	task := taskWrite{
		Path:        configLeasePath,
		Description: fmt.Sprintf("AWS root config [%s]", configLeasePath),
		Data:        structToMap(secretsEngineAWS.ConfigLease),
	}
	wg.Add(1)
	taskChan <- task

	// Create/Update Roles
	for role_name, role := range secretsEngineAWS.Roles {
		rolePath := path.Join(secretsEngine.Path, "roles", role_name)
		task := taskWrite{
			Path:        rolePath,
			Description: fmt.Sprintf("AWS role [%s]", rolePath),
			Data:        structToMap(role),
		}
		wg.Add(1)
		taskChan <- task
		if err != nil {
			log.Fatal("Error creating/updating role ["+role_name+"] at ["+secretsEngine.Path+"]", err)
		}
	}

	// Cleanup Roles
	cleanupAwsRoles(secretsEngine, secretsEngineAWS)
}

func getAwsRoles(secretsEngine *SecretsEngine, secretsEngineAWS *SecretsEngineAWS) {

	secretsEngineAWS.Roles = make(map[string]awsRoleEntry)

	roleConfigDirPath := path.Join(Spec.ConfigurationPath, "secrets-engines", secretsEngine.Path, "roles")
	rawRoles := processDirectoryRaw(roleConfigDirPath)
	for roleName, rawRole := range rawRoles {
		var role awsRoleEntry
		err := json.Unmarshal(rawRole, &role)
		if err != nil {
			log.Fatalf("Error parsing AWS role [%s]: %v", path.Join(roleConfigDirPath, roleName), err)
		}

		// Marshal the raw policy document to a string
		if role.RawPolicy != nil {
			raw_policy, err := json.Marshal(role.RawPolicy)
			if err != nil {
				log.Fatalf("Error parsing AWS role raw policy statement in [%s]: %v", path.Join(roleConfigDirPath, roleName), err)
			}
			role.PolicyDocument = string(raw_policy)
			role.RawPolicy = nil
		}

		secretsEngineAWS.Roles[roleName] = role
	}
}

func cleanupAwsRoles(secretsEngine SecretsEngine, secretsEngineAWS SecretsEngineAWS) {

	existing_roles := getSecretList(secretsEngine.Path + "roles")
	for _, role := range existing_roles {
		rolePath := secretsEngine.Path + "roles/" + role
		if _, ok := secretsEngineAWS.Roles[role]; ok {
			log.Debug("[" + rolePath + "] exists in configuration, no cleanup necessary")
		} else {
			task := taskDelete{
				Description: fmt.Sprintf("AWS role [%s]", rolePath),
				Path:        rolePath,
			}
			taskPromptChan <- task
		}
	}
}
