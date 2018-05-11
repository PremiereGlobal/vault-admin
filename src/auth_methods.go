package main

import (
  "io/ioutil"
  "encoding/json"
  "path/filepath"
  log "github.com/Sirupsen/logrus"
  VaultApi "github.com/hashicorp/vault/api"
)

type AuthMethod struct {
  Path string `json:"path"`
  AuthOptions VaultApi.EnableAuthOptions `json:"auth_options"`
  Config map[string]interface{} `json:"config"`
  PolicyMap map[string]interface{} `json:"policy_map"`
}

type AuthMethodList map[string]AuthMethod

type LdapPolicyMapping struct {
  Policies []string
}

type LdapPolicyMappingList map[string]LdapPolicyMapping

func SyncAuthMethods() {

  authMethodList := AuthMethodList{}

  log.Info("Syncing Auth Methods")
  GetAuthMethods(authMethodList)
  ConfigureAuthMethods(authMethodList)
  CleanupAuthMethods(authMethodList)
}

func GetAuthMethods(authMethodList AuthMethodList) {
  files, err := ioutil.ReadDir(Spec.ConfigurationPath+"/auth_methods/")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {

    if checkExt(file.Name(), ".json") {
      content, err := ioutil.ReadFile(Spec.ConfigurationPath+"/auth_methods/"+file.Name())
    	if err != nil {
    		log.Fatal(err)
    	}

      if (!isJSON(string(content))) {
        log.Fatal("Auth method configuration not valid JSON: ", file.Name())
      }

      var m AuthMethod

      // Use the filename as the mount path
      filename := file.Name()
      m.Path = filename[0:len(filename)-len(filepath.Ext(filename))] + "/"
      err = json.Unmarshal([]byte(content), &m)
      if err != nil {
          log.Fatal("Error parsing auth method configuration: ", file.Name(), " ", err)
      }

      authMethodList[m.Path] = m
    } else {
      log.Warn("Auth file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"/auth_methods/"+file.Name())
    }
	}
}

func ConfigureAuthMethods(authMethodList AuthMethodList) {
  for _, mount := range authMethodList {

    // Check if mount is enabled
    existing_mounts, _ := VaultSys.ListAuth();
    if _, ok := existing_mounts[mount.Path]; ok {
      if (existing_mounts[mount.Path].Type != mount.AuthOptions.Type) {
        log.Fatal("Auth mount path  " + mount.Path + " exists but doesn't match type: ", existing_mounts[mount.Path].Type, "!=", mount.AuthOptions.Type)
      }
      log.Debug("Auth mount path " + mount.Path + " already enabled and type matches, tuning for any updates");

      if (existing_mounts[mount.Path].Description != mount.AuthOptions.Description) {
        log.Warn("Unable to update description field for [" + mount.Path + "]; This is a current limitation of Vault API")
      }

      var mc VaultApi.MountConfigInput
      mc.DefaultLeaseTTL = mount.AuthOptions.Config.DefaultLeaseTTL
      mc.MaxLeaseTTL = mount.AuthOptions.Config.MaxLeaseTTL
      err := VaultSys.TuneMount("/auth/"+mount.Path, mc)
      if err != nil {
          log.Fatal("Error tuning mount: ", mount.Path, " ", err)
      }
    } else {
      log.Debug("Auth mount path " + mount.Path + " is not enabled, enabling")
      err := VaultSys.EnableAuthWithOptions(mount.Path, &mount.AuthOptions)
      if err != nil {
          log.Fatal("Error enabling mount: ", mount.Path, " ", mount.AuthOptions.Type, " ", err)
      }
      log.Info("Auth enabled: ", mount.Path, " ", mount.AuthOptions.Type)
    }

    if(mount.AuthOptions.Type == "ldap") {
      log.Info("Configuring LDAP backend ", mount.Path)
      ConfigureLDAPAuth(mount.Path, mount.Config)
      ConfigureLDAPPolicies(mount.Path, mount.PolicyMap)
    } else {
      log.Warn("Auth types other than LDAP not currently configurable, please open PR!")
    }

  }
}

func ConfigureLDAPAuth(path string, config map[string]interface{}) {
  _, err := Vault.Write("/auth/"+path+"config", config)
  if err != nil {
      log.Fatal("Error writing LDAP config for " + path + " ", err)
  }
}

func ConfigureLDAPPolicies(path string, policyMap map[string]interface{}) {
  ldapPolicyMappingList := LdapPolicyMappingList{}
  GetLdapPolicies(ldapPolicyMappingList, policyMap)
  ConfigureLdapPolicies(path, ldapPolicyMappingList)
  CleanupLdapPolicies(path, ldapPolicyMappingList)
}

func GetLdapPolicies(ldapPolicyMappingList LdapPolicyMappingList, policyMap map[string]interface{}) {

	// Loop through the items and build the mapping list
  for ldap_group, v := range policyMap {
    ldapPolicyMapping := LdapPolicyMapping{}
    ldapPolicies := &ldapPolicyMapping.Policies
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
    ldapPolicyMappingList[ldap_group] = ldapPolicyMapping
  }
}

func ConfigureLdapPolicies(path string, ldapPolicyMappingList LdapPolicyMappingList) {

  log.Debug("Writing LDAP Group -> Policy mappings for " + path)
  for ldap_name, ldapPolicyMapping := range ldapPolicyMappingList {

    log.Debug("LDAP Group [" +ldap_name+ "] -> Policies ", ldapPolicyMapping.Policies, " [" + path + "]")

    // Check if mount is enabled
    _, err := Vault.Write("/auth/" + path + "groups/"+ldap_name, map[string]interface{}{"policies": ldapPolicyMapping.Policies});
    if err != nil {
      log.Fatal("Error writing ldap group mapping [" + path + ldap_name + "]", err)
    }
  }
}

func CleanupLdapPolicies(path string, ldapPolicyMappingList LdapPolicyMappingList) {
  existing_groups, _ := Vault.List("/auth/" + path + "groups");

  for _, v := range existing_groups.Data {
    switch ldapGroups := v.(type) {
      case []interface{}:
        for _, groupArrayValue := range ldapGroups {
          switch group_name := groupArrayValue.(type) {
            case string:
              if _, ok := ldapPolicyMappingList[group_name]; ok {
                log.Debug("LDAP group mapping [" + group_name + "] exists in configuration, no cleanup necessary")
              } else {
                log.Info("LDAP group mapping [" + group_name + "] does not exist in configuration, prompting to delete")
                if( askForConfirmation("Delete LDAP group mapping [" + group_name + "] [y/n]?: ") ) {
                  _, err := Vault.Delete("/auth/" + path + "groups/" + group_name)
                  if err != nil {
                		log.Fatal("Error deleting LDAP group mapping [" + group_name + "] ", err)
                	}
                  log.Info("LDAP group mapping [" + group_name + "] deleted")
                } else {
                  log.Info("Leaving LDAP group mapping [" + group_name + "] even though it is not in config")
                }
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

func CleanupAuthMethods(authMethodList AuthMethodList) {
  existing_mounts, _ := VaultSys.ListAuth();

  for path, mount := range existing_mounts {

    // Ignore default token auth mount
    if(!(path == "token/" && mount.Type == "token")) {
      if _, ok := authMethodList[path]; ok {
        log.Debug(path + " exists in configuration, no cleanup necessary")
      } else {
        log.Info(path + " does not exist in configuration, prompting to delete")
        if( askForConfirmation("Delete auth mount " + path + " [y/n]?: ") ) {
          err := VaultSys.DisableAuth(path)
          if err != nil {
        		log.Fatal("Error deleting auth mount ", path, err)
        	}
          log.Info(path + " auth mount deleted")
        } else {
          log.Info("Leaving " + path + " even though it is not in config")
        }
      }
    }
  }
}
