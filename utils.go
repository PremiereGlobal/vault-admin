package main

import (
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

func getJsonFile(path string) (bool, string) {
	if checkExt(path, ".json") {
		content, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}

		if !isJSON(string(content)) {
			log.Fatal("File is not valid JSON: ", path)
		}

		return true, string(content)
	} else {
		log.Warn("File has wrong extension.  Will not be processed: ", path)
		return false, ""
	}
}

func getSecretArray(path string) (bool, map[string]string) {

	var secretArray map[string]string
	secretArray = make(map[string]string)

	// Read secrets from Vault for substitution
	secret, err := Vault.Read(path)
	if err != nil {
		log.Fatal(err)
	}

	if secret != nil {
		for k, v := range secret.Data {
			switch value := v.(type) {
			case string:
				secretArray[k] = value
			default:
				log.Fatal("Issue parsing Vault secret [" + path + "]")
			}
		}
	} else {
		return false, nil
	}

	return true, secretArray
}

// GetSecretListKeyInfo takes a path and performs a LIST operation on it
// If available, returns a map of key_info
// If second parameter, v, is passed, info is unmarshalled
func GetSecretListKeyInfo(path string, v interface{}) (map[string]interface{}, error) {

	secretMap := make(map[string]interface{})

	secret, err := Vault.List(path)
	if err != nil {
		return nil, err
	}

	if secret != nil {
		if _, ok := secret.Data["key_info"]; ok {
			switch value := secret.Data["key_info"].(type) {
			case map[string]interface{}:
				if v != nil {
					jsondata, err := json.Marshal(value)
					if err != nil {
						return nil, err
					}
					if err := json.Unmarshal(jsondata, v); err != nil {
						return nil, err
					}
				} else {
					return value, nil
				}
			default:
				return nil, errors.New("Secret list failed on [" + path + "], expected map[string]interface {} but got " + fmt.Sprintf("%T", value))
			}
		} else {
			return nil, errors.New("Secret list failed on [" + path + "], no \"key_info\" present")
		}
	} else {
		return nil, nil
	}

	return secretMap, nil
}

func getSecretList(path string) (bool, []string) {

	var secretArray []string

	// Read secrets from Vault for substitution
	secret, err := Vault.List(path)
	if err != nil {
		log.Fatal(err)
	}

	if secret != nil {
		for _, v := range secret.Data {
			switch value := v.(type) {
			case []interface{}:
				for _, k := range value {
					switch key := k.(type) {
					case string:
						secretArray = append(secretArray, string(key))
					default:
						log.Fatal("Issue parsing Vault secret list [" + path + "] [error 001]")
					}
				}
			default:
				log.Fatal("Issue parsing Vault secret list [" + path + "] [error 002]")
			}
		}
	} else {
		return false, nil
	}

	return true, secretArray
}

func performSubstitutions(content *string, secretPath string) (bool, string) {

	var secrets map[string]string
	success, secrets := getSecretArray(Spec.VaultSecretBasePath + secretPath)

	if success {
		for k, v := range secrets {
			*content = strings.Replace(*content, "%{"+k+"}%", v, -1)
		}
	}

	// Ensure all the variables were substituted
	re := regexp.MustCompile("(%\\{[a-zA-Z0-9_]+\\}%)")
	matches := re.FindAllStringSubmatch(*content, -1)
	if len(matches) > 0 {
		var matchArray []string
		for _, match := range matches {
			matchArray = append(matchArray, match[0])
		}
		return false, fmt.Sprintf("The following substitutions were detected but not found in Vault path ["+secretPath+"]: %v", strings.Join(matchArray, ", "))
	}

	return true, ""
}

func writeStructToVault(path string, data interface{}) error {

	// Marshal structure to get it back to JSON formatted keys
	jsondata, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var dataMap map[string]interface{}

	if err := json.Unmarshal(jsondata, &dataMap); err != nil {
		return err
	}

	_, err = Vault.Write(path, dataMap)
	if err != nil {
		return err
	}

	return nil
}

func writeStringToVault(path string, data string) error {

	var dataMap map[string]interface{}

	if err := json.Unmarshal([]byte(data), &dataMap); err != nil {
		return err
	}

	_, err := Vault.Write(path, dataMap)
	if err != nil {
		return err
	}

	return nil
}

func checkExt(filename string, ext string) bool {
	if filepath.Ext(filename) == ext {
		return true
	}

	return false
}

func isJSON(s string) bool {
	var js map[string]interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}

func askForConfirmation(msg string, max int) bool {

	if max > 0 {
		var response string
		fmt.Print(msg)
		_, err := fmt.Scanln(&response)
		if err != nil {
			log.Debug(err)
			return askForConfirmation(msg, max-1)
		}

		if strings.ToLower(string(response[0])) == "y" {
			return true
		} else if strings.ToLower(string(response[0])) == "n" {
			return false
		} else {
			fmt.Println("Invalid response.")
			return askForConfirmation(msg, max-1)
		}
	}

	log.Warning("Max number of invalid confirmations reached, exiting with 'n' response")
	return false
}

// structToMap takes in an arbitrary interface and converts it into a map[string]interface{}
// using the json/yaml tags
// This is the format that Vault uses for writing data
func structToMap(item interface{}) map[string]interface{} {
	jsonData, err := json.Marshal(&item)
	if err != nil {
		log.Fatalf("Unable to marshall struct: %v", err)
	}

	var mm map[string]interface{}
	err = json.Unmarshal(jsonData, &mm)
	if err != nil {
		log.Fatalf("Unable to unmarshall struct: %v", err)
	}

	return mm
}
