package main

import (
	"strings"
)

type cleanupAuthMethodUserpassTask struct {
	path     string
	userList UserList
}

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

	cleanupAuthMethodUserpassTask := cleanupAuthMethodUserpassTask{
		path:     auth.Path,
		userList: userList,
	}
	taskPromptChan <- cleanupAuthMethodUserpassTask
}

func userpassAddUsers(path string, userList UserList) {
	// Loop through the items and build the mapping list
	for username, data := range userList {

		// Assert our user object
		u := data.(map[string]interface{})

		// Write the user config
		log.Debug("Writing user [" + username + "]...")
		_, err := Vault.Write("/auth/"+path+"users/"+username, u)
		if err != nil {
			log.Fatal("Error writing userpass user", err)
		}
	}
}

func (c cleanupAuthMethodUserpassTask) run(workerNum int) bool {
	existing_users, _ := Vault.List("/auth/" + c.path + "users")

	for _, v := range existing_users.Data {
		switch userpassUsers := v.(type) {
		case []interface{}:

			for _, userpassUser := range userpassUsers {
				switch username := userpassUser.(type) {
				case string:
					if _, ok := c.userList[username]; ok {
						log.Debug("Userpass user [" + c.path + username + "] exists in configuration, no cleanup necessary")
					} else {
						log.Info("Userpass user [" + c.path + username + "] does not exist in configuration, prompting to delete")
						if askForConfirmation("Delete Userpass user [" + c.path + username + "]") {
							_, err := Vault.Delete("/auth/" + c.path + "users/" + username)
							if err != nil {
								log.Fatal("Error deleting Userpass user ["+c.path+username+"] ", err)
							}
							log.Info("Userpass user [" + c.path + username + "] deleted")
						} else {
							log.Info("Leaving Userpass user [" + c.path + username + "] even though it is not in config")
						}
					}
				default:
					log.Fatal("Issue parsing Userpass user from Vault [" + c.path + "]")
				}
			}
		default:
			log.Fatal("Issue parsing Userpass users from Vault [" + c.path + "]")
		}
	}

	return true
}
