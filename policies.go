package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"path"
)

type Policy struct {
	Name           string `json:"name",yaml:"name"`
	PolicyDocument string `json:"policy",yaml:"policy"`
}

var policyList SecretList

func SyncPolicies() {

	log.Info("Syncing Policies")

	// Create/Update Policies
	rawPolicies := processDirectoryRaw(path.Join(Spec.ConfigurationPath, "policies"))
	for policyName, rawPolicyDocument := range rawPolicies {
		policy := Policy{Name: policyName, PolicyDocument: string(rawPolicyDocument)}
		policyPath := path.Join("sys/policies/acl", policy.Name)
		task := taskWrite{
			Path:        policyPath,
			Description: fmt.Sprintf("Policy [%s]", policy.Name),
			Data:        structToMap(policy),
		}
		wg.Add(1)
		taskChan <- task

		policyList.Add(policyName)
	}

	// Clean up Policies
	existing_policies, _ := VaultSys.ListPolicies()
	for _, policy := range existing_policies {
		// Ignore root and default policies. These cannot be removed
		if !(policy == "root" || policy == "default") {
			if policyList.Contains(policy) {
				log.Debug(policy + " exists in configuration, no cleanup necessary")
			} else {
				task := taskDelete{
					Description: fmt.Sprintf("Policy [%s]", policy),
					Path:        path.Join("sys/policies/acl", policy),
				}
				taskPromptChan <- task
			}
		}
	}
}
