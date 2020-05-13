package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"path"
	"strings"
)

type UserList map[string]interface{}

// configureUserpassAuth creates/updates an userpass auth method
func configureUserpassAuth(auth authMethod) {

	// Pull the users out of the additional config
	additionalConfig := auth.AdditionalConfig.(map[string]interface{})
	usersData := additionalConfig["users"].([]interface{})

	// Create our user list
	userList := UserList{}
	for _, user := range usersData {
		u := user.(map[string]interface{})
		username := u["username"].(string)
		// Lower the username because that's how Vault stores them
		userList[strings.ToLower(username)] = u
	}

	userpassAddUsers(auth.Path, userList)
	cleanupUserpassUsers(auth.Path, userList)
}

func userpassAddUsers(authPath string, userList UserList) {
	// Loop through the items and build the mapping list
	for username, data := range userList {
		userPath := path.Join("auth", authPath, "users", username)
		task := taskWrite{
			Path:        userPath,
			Description: fmt.Sprintf("Userpass user [%s] ", userPath),
			Data:        data.(map[string]interface{}),
		}
		wg.Add(1)
		taskChan <- task
	}
}

func cleanupUserpassUsers(authPath string, userList UserList) {
	existing_users, err := Vault.List("/auth/" + authPath + "users")
	if err != nil {
		log.Fatalf("Error fetching Userpass users [%s]", "/auth/"+authPath+"users")
	}

	if existing_users != nil {
		for _, v := range existing_users.Data {
			switch userpassUsers := v.(type) {
			case []interface{}:

				for _, userpassUser := range userpassUsers {
					switch username := userpassUser.(type) {
					case string:
						if _, ok := userList[username]; ok {
							log.Debugf("Userpass user [%s%s] exists in configuration, no cleanup necessary", authPath, username)
						} else {
							userPath := path.Join("auth", authPath, "users", username)
							task := taskDelete{
								Description: fmt.Sprintf("Userpass user [%s]", userPath),
								Path:        userPath,
							}
							taskPromptChan <- task
						}
					default:
						log.Fatalf("Issue parsing Userpass user from Vault [%s]", authPath)
					}
				}
			default:
				log.Fatalf("Issue parsing Userpass users from Vault [%s]", authPath)
			}
		}
	}
}
