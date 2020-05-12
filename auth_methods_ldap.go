package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"path"
)

type LdapPolicyMap map[string]LdapPolicyItem

type LdapPolicyItem struct {
	Policies []string
}

// ConfigureLdapAuth creates/updates an LDAP auth method
func configureLDAPAuth(auth authMethod) {

	// Pull the policy map out of the additional config
	additionalConfig := auth.AdditionalConfig.(map[string]interface{})
	policyMap := additionalConfig["policy_map"].(map[string]interface{})

	// Update polics->ldap_group config
	ldapPolicyMap := LdapPolicyMap{}
	getLdapPolicies(ldapPolicyMap, policyMap)
	configureLdapPolicies(auth.Path, ldapPolicyMap)
	cleanupLdapPolicies(auth.Path, ldapPolicyMap)
}

func getLdapPolicies(ldapPolicyMap LdapPolicyMap, policyMap map[string]interface{}) {

	// Loop through the items and build the mapping list
	for ldap_group, v := range policyMap {
		ldapPolicyItem := LdapPolicyItem{}
		ldapPolicies := &ldapPolicyItem.Policies
		switch policyArray := v.(type) {
		case []interface{}:
			for _, policyArrayValue := range policyArray {
				switch policy_name := policyArrayValue.(type) {
				case string:
					*ldapPolicies = append(*ldapPolicies, policy_name)
				default:
					log.Fatal("Issue parsing LDAP policy map. Invalid value for key [" + ldap_group + "]. Should be an array of policy names. [error 002]")
				}
			}
		default:
			log.Fatal("Issue parsing LDAP policy map. Invalid value for key [" + ldap_group + "].  Should be an array of policy names. [error 001]")
		}
		ldapPolicyMap[ldap_group] = ldapPolicyItem
	}
}

func configureLdapPolicies(authPath string, ldapPolicyMap LdapPolicyMap) {
	for ldap_name, ldapPolicyItem := range ldapPolicyMap {
		groupPath := path.Join("auth", authPath, "groups", ldap_name)
		task := taskWrite{
			Path:        groupPath,
			Description: fmt.Sprintf("LDAP group policy map [%s] ", groupPath),
			Data:        map[string]interface{}{"policies": ldapPolicyItem.Policies},
		}
		wg.Add(1)
		taskChan <- task
	}
}

func cleanupLdapPolicies(authPath string, ldapPolicyMap LdapPolicyMap) {
	existing_groups, err := Vault.List("/auth/" + authPath + "groups")
	if err != nil {
		log.Fatalf("Error fetching LDAP groups [%s]", "/auth/"+authPath+"groups")
	}

	if existing_groups != nil {
		for _, v := range existing_groups.Data {
			switch ldapGroups := v.(type) {
			case []interface{}:
				for _, groupArrayValue := range ldapGroups {
					switch group_name := groupArrayValue.(type) {
					case string:
						if _, ok := ldapPolicyMap[group_name]; ok {
							log.Debug("LDAP group mapping [" + group_name + "] exists in configuration, no cleanup necessary")
						} else {
							groupPath := path.Join("auth", authPath, "groups", group_name)
							task := taskDelete{
								Description: fmt.Sprintf("LDAP group policy map [%s]", groupPath),
								Path:        groupPath,
							}
							taskPromptChan <- task
						}
					default:
						log.Fatal("Issue parsing LDAP groups mapping from Vault [error 002]")
					}
				}
			default:
				log.Fatal("Issue parsing LDAP groups mapping from Vault [error 001]")
			}
		}
	}
}
