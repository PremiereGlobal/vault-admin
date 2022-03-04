package main

import (
	"encoding/json"
	"fmt"
	"path"

	log "github.com/sirupsen/logrus"
)

type AuthMethodKubernetes struct {
	// Path to the auth backend
	Path string

	// AdditionalConfig for the auth backend (for example role or group mapping configurations)
	AdditionalConfig interface{}

	configuredRoleList SecretList
}

type AuthMethodKubernetesAdditionalConfig struct {
	Roles []KubernetesRole `json:"roles" yaml:"roles"`
}

// Kubernetes Role
// https://www.vaultproject.io/api-docs/auth/kubernetes#create-role
type KubernetesRole struct {

	// List of service account names able to access this role. If set to "*" all names are allowed.
	// https://www.vaultproject.io/api-docs/auth/kubernetes#bound_service_account_names
	BoundServiceAccountNames []string `json:"bound_service_account_names" yaml:"bound_service_account_names"`

	// List of namespaces allowed to access this role. If set to "*" all namespaces are allowed.
	// https://www.vaultproject.io/api-docs/auth/kubernetes#bound_service_account_namespaces
	BoundServiceAccountNamespaces []string `json:"bound_service_account_namespaces" yaml:"bound_service_account_namespaces"`

	// Optional Audience claim to verify in the JWT.
	// https://www.vaultproject.io/api-docs/auth/kubernetes#audience
	Audience string `json:"audience" yaml:"audience"`

	// Configures how identity aliases are generated. Valid choices are: serviceaccount_uid, serviceaccount_name
	// When serviceaccount_uid is specified, the machine generated UID from the service account will be used as the
	// identity alias name. When serviceaccount_name is specified, the service account's namespace and name will be
	// used as the identity alias name e.g vault/vault-auth. While it is strongly advised that you use serviceaccount_uid,
	// you may also use serviceaccount_name in cases where you want to set the alias ahead of time, and the risks are
	// mitigated or otherwise acceptable given your use case. It is very important to limit who is able to delete/create
	// service accounts within a given cluster. See the Create an Entity Alias document which further expands on the
	// potential security implications mentioned above.
	// https://www.vaultproject.io/api-docs/auth/kubernetes#alias_name_source
	AliasNameSource string `json:"alias_name_source" yaml:"alias_name_source"`

	TokenAttributes
}

func (auth *AuthMethodKubernetes) Configure() {

	// Marshall and unmarshall back into our struct
	jsonData, err := json.Marshal(&auth.AdditionalConfig)
	if err != nil {
		log.Fatalf("Unable to marshall additional_config for [%s]: %v", auth.Path, err)
	}

	var config AuthMethodKubernetesAdditionalConfig
	err = json.Unmarshal(jsonData, &config)
	if err != nil {
		log.Fatalf("Unable to unmarshall additional_config for [%s]: %v", auth.Path, err)
	}

	for i, role := range config.Roles {
		if role.Name != "" {
			auth.setRoleDefaults(&role)
			rolePath := path.Join(auth.Path, "role", role.Name)
			task := taskWrite{
				Path:        rolePath,
				Description: fmt.Sprintf("Kubernetes role [%s]", rolePath),
				Data:        structToMap(role),
			}
			wg.Add(1)
			taskChan <- task
			auth.configuredRoleList = append(auth.configuredRoleList, role.Name)
		} else {
			log.Fatalf("Error parsing additional_config.roles[%d] on auth method [%s]. Missing 'name' field.", i, auth.Path)
		}
	}

	auth.Cleanup()
}

func (auth *AuthMethodKubernetes) Cleanup() {

	// There is no "key_info" for listing roles so we just use a regular list
	existingRoles := getSecretList(path.Join(auth.Path, "role"))

	// The data that is returned from Vault is not exactly in the right format for our needs so we need to tweak it
	for _, roleName := range existingRoles {
		rolePath := path.Join(auth.Path, "role", roleName)
		if auth.configuredRoleList.Contains(roleName) {
			log.Debugf("Kubernetes role [%s] exists in configuration, no cleanup necessary", rolePath)
		} else {
			task := taskDelete{
				Description: fmt.Sprintf("Kubernetes role [%s]", rolePath),
				Path:        rolePath,
			}
			taskPromptChan <- task
		}
	}
}

func (auth *AuthMethodKubernetes) setRoleDefaults(role *KubernetesRole) {
	if role.AliasNameSource == "" {
		role.AliasNameSource = "serviceaccount_uid"
	}
}
