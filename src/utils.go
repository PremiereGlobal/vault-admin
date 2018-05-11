package main

import (
  "path/filepath"
  "encoding/json"
  "strings"
  "fmt"
  "io/ioutil"
  "regexp"
  log "github.com/Sirupsen/logrus"
)

func getJsonFile(path string) (bool, string) {
  if checkExt(path, ".json") {
    content, err := ioutil.ReadFile(path)
    if err != nil {
      log.Fatal(err)
    }

    if (!isJSON(string(content))) {
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

  if(secret != nil) {
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

func getSecretList(path string) (bool, []string) {

  var secretArray []string

  // Read secrets from Vault for substitution
  secret, err := Vault.List(path)
  if err != nil {
    log.Fatal(err)
  }

  if(secret != nil) {
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

  if(success) {
    for k, v := range secrets {
      *content = strings.Replace(*content, "%{"+k+"}%", v, -1)
    }
  }

  // Ensure all the variables were substituted
  re := regexp.MustCompile("(%\\{[a-zA-Z0-9_]+\\}%)")
  matches := re.FindAllStringSubmatch(*content, -1)
  if(len(matches) > 0) {
    var matchArray []string
    for _, match := range matches {
      matchArray = append(matchArray, match[0])
    }
    return false, fmt.Sprintf("The following substitutions were detected but not found in Vault path [" + secretPath + "]: %v", strings.Join(matchArray, ", "))
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

func askForConfirmation(msg string) bool {

  var response string
  fmt.Print(msg)
	_, err := fmt.Scanln(&response)
	if err != nil {
    log.Debug(err)
		return askForConfirmation(msg)
	}

	if strings.ToLower(string(response[0])) == "y" {
		return true
	} else if strings.ToLower(string(response[0])) == "n" {
		return false
	} else {
		fmt.Println("Invalid response.")
		return askForConfirmation(msg)
	}
}
