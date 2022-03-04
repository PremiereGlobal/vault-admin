package main

import (
	"encoding/json"
	"fmt"
	"path"
	"time"

	log "github.com/sirupsen/logrus"
)

type AuthMethodJWT struct {
	// Path to the auth backend (i.e. /auth/ldap)
	Path string

	// AdditionalConfig for the auth backend (for example role or group mapping configurations)
	AdditionalConfig interface{}

	configuredRoleList SecretList
}

type AuthMethodJWTAdditionalConfig struct {
	Roles []jwtRole `json:"roles",yaml:"roles"`
}

// Lifeted from https://github.com/hashicorp/vault-plugin-auth-jwt/blob/master/path_role.go
// Would rather use that file and not redeclare except we need to support yaml (and is missing "Name" field)
// Need to marshall into a struct so that omitted fields are updated to defaults
type jwtRole struct {
	Name     string `json:"name",yaml:"name"`
	RoleType string `json:"role_type",yaml:"role_type",default:"oidc"`

	// Duration of leeway for expiration to account for clock skew
	ExpirationLeeway time.Duration `json:"expiration_leeway",yaml:"expiration_leeway"`

	// Duration of leeway for not before to account for clock skew
	NotBeforeLeeway time.Duration `json:"not_before_leeway",yaml:"not_before_leeway"`

	// Duration of leeway for all claims to account for clock skew
	ClockSkewLeeway time.Duration `json:"clock_skew_leeway",yaml:"clock_skew_leeway",default:"0"`

	// Role binding properties
	BoundAudiences      []string               `json:"bound_audiences",yaml:"bound_audiences"`
	BoundSubject        string                 `json:"bound_subject",yaml:"bound_subject"`
	BoundClaimsType     string                 `json:"bound_claims_type",yaml:"bound_claims_type"`
	BoundClaims         map[string]interface{} `json:"bound_claims",yaml:"bound_claims"`
	ClaimMappings       map[string]string      `json:"claim_mappings",yaml:"claim_mappings"`
	UserClaim           string                 `json:"user_claim",yaml:"user_claim"`
	GroupsClaim         string                 `json:"groups_claim",yaml:"groups_claim"`
	OIDCScopes          []string               `json:"oidc_scopes",yaml:"oidc_scopes"`
	AllowedRedirectURIs []string               `json:"allowed_redirect_uris",yaml:"allowed_redirect_uris"`
	VerboseOIDCLogging  bool                   `json:"verbose_oidc_logging",yaml:"verbose_oidc_logging"`

	TokenAttributes
}

func (auth *AuthMethodJWT) Configure() {

	// Marshall and unmarshall back into our struct
	jsonData, err := json.Marshal(&auth.AdditionalConfig)
	if err != nil {
		log.Fatalf("Unable to marshall additional_config for [%s]: %v", auth.Path, err)
	}

	var config AuthMethodJWTAdditionalConfig
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
				Description: fmt.Sprintf("JWT/OIDC role [%s]", rolePath),
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

func (auth *AuthMethodJWT) Cleanup() {

	// There is no "key_info" for listing roles so we just use a regular list
	existingRoles := getSecretList(path.Join(auth.Path, "role"))

	// The data that is returned from Vault is not exactly in the right format for our needs so we need to tweak it
	for _, roleName := range existingRoles {
		rolePath := path.Join(auth.Path, "role", roleName)
		if auth.configuredRoleList.Contains(roleName) {
			log.Debugf("JWT/OIDC role [%s] exists in configuration, no cleanup necessary", rolePath)
		} else {
			task := taskDelete{
				Description: fmt.Sprintf("JWT/OIDC role [%s]", rolePath),
				Path:        rolePath,
			}
			taskPromptChan <- task
		}
	}
}

func (auth *AuthMethodJWT) setRoleDefaults(role *jwtRole) {
	if role.BoundClaimsType == "" {
		role.BoundClaimsType = "string"
	}
	if role.TokenType == "" {
		role.TokenType = "default"
	}
}
