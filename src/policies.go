package main

import (
  "io/ioutil"
  "path/filepath"
  log "github.com/Sirupsen/logrus"
)

type Policy struct {
  Name string
  Rules string
}

type PolicyList map[string]Policy

func SyncPolicies() {
  policyList := PolicyList{}
  GetPolicies(policyList)
  WritePolicies(policyList)
  CleanupPolicies(policyList)
}

func GetPolicies(policyList PolicyList) {
  files, err := ioutil.ReadDir(Spec.ConfigurationPath+"/policies/")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {

    if checkExt(file.Name(), ".json") {
      content, err := ioutil.ReadFile(Spec.ConfigurationPath+"/policies/"+file.Name())
    	if err != nil {
    		log.Fatal(err)
    	}

      if (!isJSON(string(content))) {
        log.Fatal("Policy not valid JSON: ", file.Name())
      }

      var p Policy

      filename := file.Name()
      policy_name := filename[0:len(filename)-len(filepath.Ext(filename))]
      p.Rules = string(content)
      policyList[policy_name] = p

    } else {
      log.Warn("Policy file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"/policies/"+file.Name())
    }
	}
}

func WritePolicies(policyList PolicyList) {
  log.Debug("Writing policies")
  for policy_name, policy := range policyList {
    err := VaultSys.PutPolicy(policy_name, policy.Rules)
    if err != nil {
        log.Fatal(err)
    }
    log.Debug("Wrote policy: ", policy_name)
  }
}

func CleanupPolicies(policyList PolicyList) {
  existing_policies, _ := VaultSys.ListPolicies();

  for _, policy := range existing_policies {

    // Ignore root and default policies. These cannot be removed
    if(!(policy == "root" || policy == "default")) {
      if _, ok := policyList[policy]; ok {
        log.Debug(policy + " exists in configuration, no cleanup necessary")
      } else {
        log.Debug(policy + " does not exist in configuration, prompting to delete")
        if( askForConfirmation("Policy [" + policy + "] does not exist in configuration.  Delete policy [" + policy + "] [y/n]?: ") ) {
          err := VaultSys.DeletePolicy(policy)
          if err != nil {
        		log.Fatal("Error deleting policy ", policy, err)
        	}
          log.Info("[" + policy + "] policy deleted")
        } else {
          log.Info("Leaving [" + policy + "] policy even though it is not in configuration")
        }
      }
    }
  }
}
