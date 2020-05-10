package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/davecgh/go-spew/spew"
)

// type LdapPolicyMap map[string]LdapPolicyItem
//
// type LdapPolicyItem struct {
// 	Policies []string
// }

// ConfigureLdapAuth creates/updates an LDAP auth method
func configureOIDCAuth(auth authMethod) {

	additionalConfig, ok := auth.AdditionalConfig.(map[string]interface{})
	if !ok {
		log.Fatalf("Error parsing additional_config on auth method [%s]. Must be a map.", auth.Path)
	}

	if _, ok := additionalConfig["roles"]; ok {
		roles, ok := additionalConfig["roles"].([]interface{})
		if !ok {
			log.Fatalf("Error parsing additional_config.roles on auth method [%s]. Must be an array.", auth.Path)
		}

		for i, role := range roles {
			r, ok := role.(map[string]interface{})
			if !ok {
				log.Fatalf("Error parsing additional_config.roles[%d] on auth method [%s]. Must be an map[string].", i, auth.Path)
			}
			spew.Dump(r)
		}
	}




	// Update polics->ldap_group config
	// ldapPolicyMap := LdapPolicyMap{}
	// getLdapPolicies(ldapPolicyMap, policyMap)
	// configureLdapPolicies(auth.Path, ldapPolicyMap)
	// cleanupLdapPolicies(auth.Path, ldapPolicyMap)
}

// func getLdapPolicies(ldapPolicyMap LdapPolicyMap, policyMap map[string]interface{}) {
//
// 	// Loop through the items and build the mapping list
// 	for ldap_group, v := range policyMap {
// 		ldapPolicyItem := LdapPolicyItem{}
// 		ldapPolicies := &ldapPolicyItem.Policies
// 		switch policyArray := v.(type) {
// 		case []interface{}:
// 			for _, policyArrayValue := range policyArray {
// 				switch policy_name := policyArrayValue.(type) {
// 				case string:
// 					*ldapPolicies = append(*ldapPolicies, policy_name)
// 				default:
// 					log.Fatal("Issue parsing LDAP policy map. Invalid value for key [" + ldap_group + "]. Should be an array of policy names. [error 002]")
// 				}
// 			}
// 		default:
// 			log.Fatal("Issue parsing LDAP policy map. Invalid value for key [" + ldap_group + "].  Should be an array of policy names. [error 001]")
// 		}
// 		ldapPolicyMap[ldap_group] = ldapPolicyItem
// 	}
// }
//
// func configureLdapPolicies(path string, ldapPolicyMap LdapPolicyMap) {
//
// 	log.Debug("Writing LDAP Group -> Policy mappings for " + path)
// 	for ldap_name, ldapPolicyItem := range ldapPolicyMap {
//
// 		log.Debug("LDAP Group ["+ldap_name+"] -> Policies ", ldapPolicyItem.Policies, " ["+path+"]")
//
// 		// Write the group policies to Vault
// 		_, err := Vault.Write("/auth/"+path+"groups/"+ldap_name, map[string]interface{}{"policies": ldapPolicyItem.Policies})
// 		if err != nil {
// 			log.Fatal("Error writing ldap group mapping ["+path+ldap_name+"]", err)
// 		}
// 	}
// }
//
// func cleanupLdapPolicies(path string, ldapPolicyMap LdapPolicyMap) {
// 	existing_groups, _ := Vault.List("/auth/" + path + "groups")
//
// 	for _, v := range existing_groups.Data {
// 		switch ldapGroups := v.(type) {
// 		case []interface{}:
// 			for _, groupArrayValue := range ldapGroups {
// 				switch group_name := groupArrayValue.(type) {
// 				case string:
// 					if _, ok := ldapPolicyMap[group_name]; ok {
// 						log.Debug("LDAP group mapping [" + group_name + "] exists in configuration, no cleanup necessary")
// 					} else {
// 						log.Info("LDAP group mapping [" + group_name + "] does not exist in configuration, prompting to delete")
// 						if askForConfirmation("Delete LDAP group mapping ["+group_name+"] [y/n]?: ", 3) {
// 							_, err := Vault.Delete("/auth/" + path + "groups/" + group_name)
// 							if err != nil {
// 								log.Fatal("Error deleting LDAP group mapping ["+group_name+"] ", err)
// 							}
// 							log.Info("LDAP group mapping [" + group_name + "] deleted")
// 						} else {
// 							log.Info("Leaving LDAP group mapping [" + group_name + "] even though it is not in config")
// 						}
// 					}
// 				default:
// 					log.Fatal("Issue parsing LDAP groups mapping from Vault [error 002]")
// 				}
// 			}
// 		default:
// 			log.Fatal("Issue parsing LDAP groups mapping from Vault [error 001]")
// 		}
// 	}
// }
