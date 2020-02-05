package main

import (
	"io/ioutil"
	"path/filepath"
)

type syncPoliciesTask struct {
	policyList map[string]Policy
}

type configurePolicyTask struct {
	policyName string
	policy     Policy
}

type cleanupPolicyTask struct {
	policyList map[string]Policy
}

type Policy struct {
	Name  string
	Rules string
}

func (s syncPoliciesTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	log.Info("Syncing Policies")
	s.policyList = make(map[string]Policy)
	s.Load()

	for policyName, policy := range s.policyList {
		configurePolicyTask := configurePolicyTask{
			policyName: policyName,
			policy:     policy,
		}
		wg.Add(1)
		taskChan <- configurePolicyTask
	}

	// Add cleanup task
	cleanupPolicyTask := cleanupPolicyTask{
		policyList: s.policyList,
	}
	taskPromptChan <- cleanupPolicyTask

	return true
}

func (s syncPoliciesTask) Load() {
	files, err := ioutil.ReadDir(filepath.Join(Spec.ConfigurationPath, "policies"))
	if err != nil {
		log.Warn("No policies found: ", err)
	}

	for _, file := range files {

		if checkExt(file.Name(), ".json") {
			content, err := ioutil.ReadFile(Spec.ConfigurationPath + "/policies/" + file.Name())
			if err != nil {
				log.Fatal(err)
			}

			if !isJSON(string(content)) {
				log.Fatal("Policy not valid JSON: ", file.Name())
			}

			var p Policy

			filename := file.Name()
			policy_name := filename[0 : len(filename)-len(filepath.Ext(filename))]
			p.Rules = string(content)
			s.policyList[policy_name] = p

		} else {
			log.Warn("Policy file has wrong extension.  Will not be processed: ", Spec.ConfigurationPath+"/policies/"+file.Name())
		}
	}
}

func (c configurePolicyTask) run(workerNum int) bool {

	// Decrement waitgroup counter when we're done
	defer wg.Done()

	err := VaultSys.PutPolicy(c.policyName, c.policy.Rules)
	if err != nil {
		log.Fatal(err)
	}
	log.Debug("Wrote policy: ", c.policyName)

	return true
}

func (c cleanupPolicyTask) run(workerNum int) bool {
	existing_policies, _ := VaultSys.ListPolicies()

	for _, policy := range existing_policies {

		// Ignore root and default policies. These cannot be removed
		if !(policy == "root" || policy == "default") {
			if _, ok := c.policyList[policy]; ok {
				log.Debug(policy + " exists in configuration, no cleanup necessary")
			} else {
				log.Debug(policy + " does not exist in configuration, prompting to delete")
				if askForConfirmation("Policy [" + policy + "] does not exist in configuration.  Delete?") {
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

	return true
}
