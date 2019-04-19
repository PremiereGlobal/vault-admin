package main

import (
	"encoding/json"
	log "github.com/Sirupsen/logrus"
	// "github.com/davecgh/go-spew/spew"
	"io/ioutil"
	"path/filepath"
	"strings"
)

type EntityConfig struct {
	Entity        map[string]interface{} `json:"entity,omitempty"`
	EntityAliases []EntityAlias          `json:"entity-aliases,omitempty"`
	EntityGroups  []string               `json:"entity-groups,omitempty"`
}

type EntityAlias struct {
	Name          string `json:"name,omitempty"`
	MountPath     string `json:"mount_path,omitempty"`
	MountAccessor string `json:"mount_accessor,omitempty"`
	CanonicalID   string `json:"canonical_id,omitempty"`
	MountType     string `json:"mount_type,omitempty"`
}

type GroupConfig struct {
	Group map[string]interface{} `json:"group,omitempty"`
}

func configureIdentitySecretsEngine(secretsEngine SecretsEngine) {

	entityList := make(map[string]string)

	// This will hold our group members
	entityGroupList := make(map[string][]string)

	// We generate a full list of existing aliases
	entityAliasList := make(map[string]EntityAlias)
	aliasData, err := getSecretListData(secretsEngine.Path + "entity-alias/id")
	if err != nil {
		log.Fatal(err)
	}
	jsondata, err := json.Marshal(aliasData)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(jsondata, &entityAliasList)

	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "entities")
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {

		success, content := getJsonFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "entities/" + file.Name())
		if success {
			var config EntityConfig

			filename := file.Name()
			entity_name := filename[0 : len(filename)-len(filepath.Ext(filename))]
			err = json.Unmarshal([]byte(content), &config)
			if err != nil {
				log.Fatal("Error parsing entity ["+secretsEngine.Path+"entities/"+entity_name+"]", err)
			}

			// Create/Update the Entity (by Name)
			log.Debug("Writing identity entity [" + entity_name + "]...")
			_, err := Vault.Write("/identity/entity/name/"+entity_name, config.Entity)
			if err != nil {
				log.Fatal("Error writing entity ", entity_name, err)
			}
			entityList[entity_name] = entity_name

			entityData, err := Vault.Read("/identity/entity/name/" + entity_name)
			if err != nil {
				log.Fatal("Error getting CanonicalID for entity ", entity_name, err)
			}
			entityID := entityData.Data["id"].(string)

			// Create the EntityAlias
			// Mount + Alias has to be unique so we need to check if the Alias already
			// exists before creating it, if not do an update.  There currently
			// is no upsert available
			for i, aliasConfig := range config.EntityAliases {
				aliasConfig.MountAccessor = LookupAuthMountAccessor(aliasConfig.MountPath)
				aliasConfig.CanonicalID = entityID

				// Update the original object cause we use it later
				config.EntityAliases[i].MountAccessor = aliasConfig.MountAccessor
				config.EntityAliases[i].CanonicalID = aliasConfig.CanonicalID

				// See if this alias already exists
				id := getAliasId(aliasConfig.Name, aliasConfig.MountAccessor, &entityAliasList)
				if id != "" {
					log.Debug("Alias " + id + " found for [" + aliasConfig.Name + ", " + aliasConfig.MountAccessor + "], updating...")
					err := writeStructToVault("/identity/entity-alias/id/"+id, aliasConfig)
					if err != nil {
						log.Fatal("Error writing entity alias ", aliasConfig.Name, err)
					}
				} else {
					log.Debug("Alias not found for [" + aliasConfig.Name + ", " + aliasConfig.MountAccessor + "], creating...")
					err := writeStructToVault("/identity/entity-alias", aliasConfig)
					if err != nil {
						log.Fatal("Error writing entity alias ", aliasConfig.Name, err)
					}
				}
			}

			// Build the map of group > entity relationships
			for _, entityGroup := range config.EntityGroups {
				entityGroupList[entityGroup] = append(entityGroupList[entityGroup], entityID)
			}

			// Now we need to remove Aliases from Entites if they aren't in the config
			existingEntityAliases := getEntityAliases(entityID, &entityAliasList)
			for existingAliasConfigID, existingAliasConfig := range existingEntityAliases {
				found := false
				for _, aliasConfig := range config.EntityAliases {
					if existingAliasConfig.Name == aliasConfig.Name && existingAliasConfig.MountAccessor == aliasConfig.MountAccessor {
						found = true
						break
					}
				}

				if !found {
					log.Info("Entity alias " + existingAliasConfig.Name + "[" + existingAliasConfig.MountAccessor + "] on entity " + entity_name + " does not exist in configuration, prompting to delete")
					if askForConfirmation("Delete entity alias "+existingAliasConfig.Name+"["+existingAliasConfig.MountAccessor+"] on entity "+entity_name+" [y/n]?: ", 3) {
						_, err := Vault.Delete(secretsEngine.Path + "entity-alias/id/" + existingAliasConfigID)
						if err != nil {
							log.Fatal("Error deleting entity alias ["+existingAliasConfigID+"] ", err)
						}
						log.Info("Deleted entity alias " + existingAliasConfig.Name + "[" + existingAliasConfig.MountAccessor + "] on entity " + entity_name)
					} else {
						log.Info("Leaving entity alias " + existingAliasConfig.Name + "[" + existingAliasConfig.MountAccessor + "] on entity " + entity_name + " even though it is not in config")
					}
				}
			}

		} else {
			log.Warn("Identity entity file has wrong extension.  Will not be processed: ", file.Name())
		}
	}

	// Configure groups
	configureIdentityGroups(secretsEngine, entityGroupList)

	// Cleanup Entities
	cleanupEntities(secretsEngine, entityList)
}

func configureIdentityGroups(secretsEngine SecretsEngine, entityGroupList map[string][]string) {

	files, err := ioutil.ReadDir(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "groups")
	if err != nil {
		log.Fatal(err)
	}

	groupList := make(map[string]string)

	for _, file := range files {

		success, content := getJsonFile(Spec.ConfigurationPath + "/secrets-engines/" + secretsEngine.Path + "groups/" + file.Name())
		if success {

			var config GroupConfig

			filename := file.Name()
			groupName := filename[0 : len(filename)-len(filepath.Ext(filename))]
			err = json.Unmarshal([]byte(content), &config)
			if err != nil {
				log.Fatal("Error parsing identity group ["+secretsEngine.Path+"groups/"+groupName+"] ", err)
			}
			groupList[groupName] = groupName

			// Add the member entities to the group, if there are no members, warn
			config.Group["member_entity_ids"] = entityGroupList[groupName]
			if len(entityGroupList[groupName]) == 0 {
				log.Warn("Identity group [" + groupName + "] contains no members.  Consider removing it.")
			}

			// Create/Update the Group (by Name)
			log.Debug("Writing identity group [" + groupName + "]...")
			_, err := Vault.Write("/identity/group/name/"+groupName, config.Group)
			if err != nil {
				log.Fatal("Error writing identity group ", groupName, err)
			}
		}
	}

	cleanupGroups(secretsEngine, groupList)

	// Put out some warnings if there are groups in the entity configs that are not present in the current config
	for groupName, entityIDs := range entityGroupList {
		offendingEntities := ""
		for _, entityID := range entityIDs {
			entityName, err := getEntityNameByID(entityID)
			if err != nil {
				log.Fatal("Error getting entity name for entity ID ["+entityID+"] ", err)
			}
			offendingEntities = offendingEntities + entityName + ","
		}

		offendingEntities = strings.TrimSuffix(offendingEntities, ",")

		if _, ok := groupList[groupName]; !ok {
			log.Warn("Identity entities [" + offendingEntities + "] configured for group [" + groupName + "] but group does not exist.  Clean up entity configs.")
		}
	}
}

// Gets an Alias ID based on the name and mountAccessor of the alias
func getAliasId(name string, mountAccessor string, entityAliasList *map[string]EntityAlias) string {
	for aliasID, alias := range *entityAliasList {
		if alias.Name == name && alias.MountAccessor == mountAccessor {
			return aliasID
		}
	}
	return ""
}

// Gets the list of current aliases attached to a entity
func getEntityAliases(entityID string, entityAliasList *map[string]EntityAlias) map[string]EntityAlias {
	results := make(map[string]EntityAlias)
	for aliasID, alias := range *entityAliasList {
		if alias.CanonicalID == entityID {
			results[aliasID] = alias
		}
	}
	return results
}

// getEntityNameByID takes in an entity ID and fetches the associated entity name
func getEntityNameByID(entityID string) (string, error) {
	entityData, err := Vault.Read("/identity/entity/id/" + entityID)
	if err != nil {
		return "", err
	}
	entityName := entityData.Data["name"].(string)
	return entityName, nil
}

// Removes named entites that are not present in the config
func cleanupEntities(secretsEngine SecretsEngine, entityList map[string]string) {

	_, existing_entities := getSecretList(secretsEngine.Path + "entity/name")
	for _, v := range existing_entities {

		if !strings.HasPrefix(v, "entity_") {
			if _, ok := entityList[v]; ok {
				log.Debug("Entity [" + v + "] exists in configuration, no cleanup necessary")
			} else {
				log.Info("Entity [" + v + "] does not exist in configuration, prompting to delete")
				if askForConfirmation("Delete entity ["+v+"] [y/n]?: ", 3) {
					_, err := Vault.Delete(secretsEngine.Path + "entity/name/" + v)
					if err != nil {
						log.Fatal("Error deleting entity ["+v+"] ", err)
					}
					log.Info("Entity [" + v + "] deleted")
				} else {
					log.Info("Leaving entity [" + v + "] even though it is not in config")
				}
			}
		}
	}
}

// Removes named groups that are not present in the config
func cleanupGroups(secretsEngine SecretsEngine, groupList map[string]string) {

	_, existing_groups := getSecretList(secretsEngine.Path + "group/name")
	for _, v := range existing_groups {
		if _, ok := groupList[v]; ok {
			log.Debug("Identity group [" + v + "] exists in configuration, no cleanup necessary")
		} else {
			log.Info("Identity group [" + v + "] does not exist in configuration, prompting to delete")
			if askForConfirmation("Delete identity group ["+v+"] [y/n]?: ", 3) {
				_, err := Vault.Delete(secretsEngine.Path + "group/name/" + v)
				if err != nil {
					log.Fatal("Error deleting identity group ["+v+"] ", err)
				}
				log.Info("Identity group [" + v + "] deleted")
			} else {
				log.Info("Leaving identity group [" + v + "] even though it is not in config")
			}
		}
	}
}

// LookupAuthMountAccessor returns the accessor_id of the auth mount
// configured at `path`
func LookupAuthMountAccessor(path string) string {
	authMounts, _ := VaultSys.ListAuth()
	for mountPath, mount := range authMounts {
		if mountPath == path {
			return mount.Accessor
		}
	}

	return ""
}
