package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PremiereGlobal/vault-admin/pkg/auth"
	"github.com/PremiereGlobal/vault-admin/pkg/secrets-engines/identity"
	log "github.com/sirupsen/logrus"
)

// This is our identity waitgroup used to halt progress between blocking async tasks within identity
var identWG sync.WaitGroup

type IdentitySecretsEngine struct {
	// The mountpath of the identity engine (i.e. /identity)
	MountPath string

	// groupMemberEntities contains a map where the key is the group name and the value is a list of member entity names
	groupMembersEntities map[string][]string

	// groupMembersGroups contains a map where the key is the parent group name and the value is a list of member group names
	groupMembersGroups map[string][]string

	// entities contains our configured list of entities
	entities identity.EntityList

	// existingEntities contains a list of existing entities in Vault
	existingEntities identity.EntityList

	// groups contains our configured list of groups
	groups identity.GroupList

	// existingGroups contains a list of existing groups in Vault
	existingGroups identity.GroupList

	// entityAliases contains our configured list of entities aliases
	entityAliases map[string]map[string]identity.Alias

	// existingEntityAliases contains a list of entity aliases in Vault
	existingEntityAliases identity.AliasList

	// groupAliases contains our configured list of group aliases
	groupAliases map[string]map[string]identity.Alias

	// existingGroupAliases contains a list of group aliases in Vault
	existingGroupAliases identity.AliasList

	// authMounts contains a mapping of auth paths to auth.Mounts
	authMounts map[string]auth.Mount
}

type EntityConfig struct {
	Entity        identity.Entity  `json:"entity,omitempty"`
	EntityAliases []identity.Alias `json:"entity-aliases,omitempty"`
	EntityGroups  []string         `json:"entity-groups,omitempty"`
}

type GroupConfig struct {
	Group       identity.Group `json:"group,omitempty"`
	GroupAlias  identity.Alias `json:"group-alias,omitempty"`
	GroupGroups []string       `json:"group-groups,omitempty"`
}

func (ident *IdentitySecretsEngine) run() {

	// Process Step 1
	// * Fetch auth mounts (to do path/accessor mapping)
	// * Upserts all entity data
	ident.fetchAuthMounts()
	ident.processEntities()
	identWG.Wait()

	// Process Step 2
	// * Insert NEW groups (goroutine) - We can't upsert all groups because we don't have all the ids for memberships yet (group of groups)
	ident.processGroups()
	identWG.Wait()

	// Process Step 3
	// * Apply all the group configuration updates (memberships, metadata, etc)
	// * Insert/Update entity and group Aliases
	ident.applyGroupUpdates()
	ident.processAliases()
	identWG.Wait()

	// Process Step 4
	// * Run cleanup tasks
	ident.cleanupEntities()
	ident.cleanupGroups()
	ident.cleanupAliases()

}

// processEntities does the following:
// * Reads in entity data from files
// * Upsert entity data (async goroutine)
// * Sets ident.groupMembersEntities (entity/group relationship)
// * Sets ident.entities (map of configured entities)
func (ident *IdentitySecretsEngine) processEntities() {

	ident.groupMembersEntities = make(map[string][]string)
	ident.entities = make(identity.EntityList)
	ident.entityAliases = make(map[string]map[string]identity.Alias)

	files, err := ioutil.ReadDir(path.Join(Spec.ConfigurationPath, "secrets-engines", ident.MountPath, "entities"))
	if err != nil {
		log.Fatalf("Error reading identity entity configurations: %v", err)
	}

	for _, file := range files {

		success, content := getJsonFile(path.Join(Spec.ConfigurationPath, "secrets-engines", ident.MountPath, "entities", file.Name()))
		if success {
			var config EntityConfig

			filename := file.Name()
			entityName := filename[0 : len(filename)-len(filepath.Ext(filename))]
			err = json.Unmarshal([]byte(content), &config)
			if err != nil {
				log.Fatalf("Error parsing entity file '%s': %v", path.Join(ident.MountPath, "entities/", entityName), err)
			}
			config.Entity.Name = entityName

			// task := taskEntityWriter{MountPath: ident.MountPath, Entity: config.Entity}
			task := taskWrite{
				Path:        path.Join(ident.MountPath, "entity/name", entityName),
				Description: fmt.Sprintf("Identity entity [%s]", entityName),
				Data:        structToMap(config.Entity),
				Defer:       func() { identWG.Done() },
			}
			wg.Add(1)
			identWG.Add(1)
			taskChan <- task

			// Save our configured entity
			ident.entities[entityName] = config.Entity

			// Build the map of group/entity relationships
			for _, entityGroup := range config.EntityGroups {
				ident.groupMembersEntities[entityGroup] = append(ident.groupMembersEntities[entityGroup], entityName)
			}

			// Build the map of aliases
			for _, entityAlias := range config.EntityAliases {
				ident.validateAndSetAlias(entityAlias, ident.entityAliases, "entity", entityName)
			}
		}
	}
}

// fetchEntities reads in existing entities data from Vault
// This is needed for cleanup as well as getting the IDs for entities present in the config
func (ident *IdentitySecretsEngine) fetchEntities() {

	keyInfo := make(identity.EntityList)
	ident.existingEntities = make(identity.EntityList)

	_, err := GetSecretListKeyInfo(path.Join(ident.MountPath, "entity/id"), &keyInfo)
	if err != nil {
		log.Fatalf("Error fetching existing entities: %v", err)
	}

	// The data that is returned from Vault is not exactly in the right format for our needs so we need to tweak it
	for id, entity := range keyInfo {
		entity.ID = id
		ident.existingEntities[entity.Name] = entity
	}
}

// fetchGroups reads in existing groups data from Vault
// This is needed for cleanup as well as getting the IDs for groups present in the config
func (ident *IdentitySecretsEngine) fetchGroups() {
	keyInfo := make(identity.GroupList)
	ident.existingGroups = make(identity.GroupList)

	_, err := GetSecretListKeyInfo(path.Join(ident.MountPath, "group/id"), &keyInfo)
	if err != nil {
		log.Fatalf("Error fetching existing entities: %v", err)
	}

	// The data that is returned from Vault is not exactly in the right format for our needs so we need to tweak it
	for id, group := range keyInfo {
		group.ID = id
		ident.existingGroups[group.Name] = group
	}

}

// processGroups does the following:
// * Loads existing groups from Vault
// * Reads in group data from files
// * Inserts new group data from config
//   We only want to write new groups because we don't have all the group
//   heirarchy built yet and we need to get the IDs for newly created groups
// * Sets ident.groupMembersGroups (group/group relationship)
// * Sets ident.groups (map of configured groups)
func (ident *IdentitySecretsEngine) processGroups() {

	// Get our existing groups (so we can insert new ones)
	ident.fetchGroups()

	ident.groupMembersGroups = make(map[string][]string)
	ident.groups = make(identity.GroupList)
	ident.groupAliases = make(map[string]map[string]identity.Alias)

	files, err := ioutil.ReadDir(path.Join(Spec.ConfigurationPath, "secrets-engines", ident.MountPath, "groups"))
	if err != nil {
		log.Fatalf("Error reading identity group configurations: %v", err)
	}

	// For each group, build the data
	for _, file := range files {

		success, content := getJsonFile(path.Join(Spec.ConfigurationPath, "secrets-engines", ident.MountPath, "groups", file.Name()))
		if success {

			var config GroupConfig

			filename := file.Name()
			groupName := filename[0 : len(filename)-len(filepath.Ext(filename))]
			err = json.Unmarshal([]byte(content), &config)
			if err != nil {
				log.Fatalf("Error parsing identity group [%s]: %v", path.Join(ident.MountPath, "groups", groupName), err)
			}
			config.Group.Name = groupName

			// If this is a new group, do a preliminary write of the data (so we can get the ID later)
			if _, ok := ident.existingGroups[groupName]; !ok {
				task := taskWrite{
					Path:        path.Join(ident.MountPath, "group/name/", groupName),
					Description: fmt.Sprintf("Identity group [%s]", groupName),
					Data:        structToMap(config.Group),
					Defer:       func() { identWG.Done() },
				}
				wg.Add(1)
				identWG.Add(1)
				taskChan <- task
			}

			// Save our configured group
			ident.groups[groupName] = config.Group

			// Build the map of group/group relationships
			for _, entityGroup := range config.GroupGroups {
				ident.groupMembersGroups[entityGroup] = append(ident.groupMembersGroups[entityGroup], groupName)
			}

			// Build the map of aliases
			if config.GroupAlias.Name != "" || config.GroupAlias.MountPath != "" || config.GroupAlias.MountAccessor != "" {
				ident.validateAndSetAlias(config.GroupAlias, ident.groupAliases, "group", groupName)
			}
		}
	}
}

func (ident *IdentitySecretsEngine) validateAndSetAlias(alias identity.Alias, aliasList map[string]map[string]identity.Alias, objectType string, objectName string) {

	if alias.Name == "" {
		log.Warnf("Alias for %s [%s] missing 'name' field, skipping...", objectType, objectName)
		return
	}

	if alias.MountAccessor != "" && alias.MountPath != "" {
		log.Fatalf("Error creating alias for %s [%s]: Only one of 'mount_accessor' or 'mount_path' can be specified", objectType, objectName)
	}

	if alias.MountAccessor == "" && alias.MountPath == "" {
		log.Fatalf("Error creating alias for %s [%s]: Either 'mount_accessor' or 'mount_path' is required", objectType, objectName)
	}

	// Set the accessor if not set
	if alias.MountAccessor == "" {
		if _, ok := ident.authMounts[alias.MountPath]; ok {
			alias.MountAccessor = ident.authMounts[alias.MountPath].Accessor
		} else {
			log.Warnf("Alias for %s [%s] contains an invalid mount_path [%s].  Ensure mount is valid and in the format '<path>/'. Alias will be skipped", objectType, objectName, alias.MountPath)
			return
		}
	}

	// Warn if this unique alias has already be set
	if _, ok := aliasList[alias.MountAccessor][alias.Name]; ok {
		log.Warnf("Duplicate alias [%s/%s] for %s [%s] will not be applied", alias.MountAccessor, alias.Name, objectType, objectName)
	} else {
		if aliasList[alias.MountAccessor] == nil {
			aliasList[alias.MountAccessor] = make(map[string]identity.Alias)
		}
		alias.CanonicalName = objectName
		aliasList[alias.MountAccessor][alias.Name] = alias
	}

}

// applyGroupUpdates writes all group data to Vault
func (ident *IdentitySecretsEngine) applyGroupUpdates() {

	// Get our existing groups (in case any new ones were added)
	ident.fetchGroups()
	ident.fetchEntities()

	// This loop sets the ID of the group as well as the members IDs for the groups
	// and then writes the group to Vault
	for groupName := range ident.groups {
		group := ident.groups[groupName]
		group.ID = ident.existingGroups[groupName].ID

		for _, memberEntityName := range ident.groupMembersEntities[groupName] {
			group.MemberEntityIDs = append(group.MemberEntityIDs, ident.existingEntities[memberEntityName].ID)
		}

		for _, memberGroupName := range ident.groupMembersGroups[groupName] {
			group.MemberGroupIDs = append(group.MemberGroupIDs, ident.existingGroups[memberGroupName].ID)
		}
		ident.groups[groupName] = group

		// Write the group data to Vault (async)
		task := taskWrite{
			Path:        path.Join(ident.MountPath, "group/name/", groupName),
			Description: fmt.Sprintf("Identity group [%s]", groupName),
			Data:        structToMap(ident.groups[groupName]),
			Defer:       func() { identWG.Done() },
		}
		wg.Add(1)
		identWG.Add(1)
		taskChan <- task
	}

	// Warn of any groups or entities trying to be a member of a group that doens't exist
	for groupName, entityList := range ident.groupMembersEntities {
		if _, ok := ident.groups[groupName]; !ok {
			for _, memberEntityName := range entityList {
				log.Warnf("Entity [%s] cannot be part of group [%s] because it does not exist", memberEntityName, groupName)
			}
		}
	}
	for groupName, groupList := range ident.groupMembersGroups {
		if _, ok := ident.groups[groupName]; !ok {
			for _, memberGroupName := range groupList {
				log.Warnf("Group [%s] cannot be part of group [%s] because it does not exist", memberGroupName, groupName)
			}
		}
	}
}

func (ident *IdentitySecretsEngine) fetchAliases(objectType string, aliasList identity.AliasList) {

	if aliasList == nil {
		aliasList = make(identity.AliasList)
	}

	existingAliases := make(identity.AliasList)
	_, err := GetSecretListKeyInfo(path.Join(ident.MountPath, fmt.Sprintf("%s-alias/id", objectType)), &existingAliases)
	if err != nil {
		log.Fatalf("Error fetching identity %s aliases: %v", objectType, err)
	}

	for id, alias := range existingAliases {
		alias.ID = id
		aliasList[id] = alias
	}
}

func (ident *IdentitySecretsEngine) processAliases() {

	ident.fetchEntities()

	ident.existingEntityAliases = make(identity.AliasList)
	ident.existingGroupAliases = make(identity.AliasList)

	ident.fetchAliases("entity", ident.existingEntityAliases)
	ident.fetchAliases("group", ident.existingGroupAliases)

	for _, aliases := range ident.entityAliases {
		for _, aliasData := range aliases {
			aliasData.CanonicalID = ident.existingEntities[aliasData.CanonicalName].ID
			if ok, id := ident.existingEntityAliases.Exists(aliasData); ok {
				aliasData.ID = id
			}

			task := taskWrite{
				Path:        path.Join(ident.MountPath, fmt.Sprintf("%s-alias", "entity")),
				Description: fmt.Sprintf("Identity %s alias [%s/%s]", "entity", aliasData.MountAccessor, aliasData.Name),
				Data:        structToMap(aliasData.CleanFields()),
				Defer:       func() { identWG.Done() },
			}
			wg.Add(1)
			identWG.Add(1)
			taskChan <- task
		}
	}

	for _, aliases := range ident.groupAliases {
		for _, aliasData := range aliases {
			aliasData.CanonicalID = ident.existingGroups[aliasData.CanonicalName].ID
			if ok, id := ident.existingGroupAliases.Exists(aliasData); ok {
				aliasData.ID = id
			}

			task := taskWrite{
				Path:        path.Join(ident.MountPath, fmt.Sprintf("%s-alias", "group")),
				Description: fmt.Sprintf("Identity %s alias [%s/%s]", "group", aliasData.MountAccessor, aliasData.Name),
				Data:        structToMap(aliasData.CleanFields()),
				Defer:       func() { identWG.Done() },
			}
			wg.Add(1)
			identWG.Add(1)
			taskChan <- task
		}
	}
}

// cleanupEntities removes entities that are not present in the config
func (ident *IdentitySecretsEngine) cleanupEntities() {
	ident.fetchEntities()
	for _, v := range ident.existingEntities {
		if _, ok := ident.entities[v.Name]; ok {
			log.Debugf("Identity entity [%s] exists in configuration, no cleanup necessary", v.Name)
		} else {
			// Don't delete entries prefixed with entity_
			// These entities are auto-generated by auth backends and it cannot be known
			// if these are valid or not
			if strings.HasPrefix(v.Name, "entity_") {
				continue
			}

			task := taskDelete{
				Description: fmt.Sprintf("Identity entity [%s]", v.Name),
				Path:        path.Join(ident.MountPath, "entity/name", v.Name),
			}
			taskPromptChan <- task
		}
	}
}

// cleanupGroups removes groups that are not present in the config
func (ident *IdentitySecretsEngine) cleanupGroups() {
	ident.fetchGroups()
	for _, v := range ident.existingGroups {
		if _, ok := ident.groups[v.Name]; ok {
			log.Debugf("Identity group [%s] exists in configuration, no cleanup necessary", v.Name)
		} else {
			task := taskDelete{
				Description: fmt.Sprintf("Identity group [%s]", v.Name),
				Path:        path.Join(ident.MountPath, "group/name", v.Name),
			}
			taskPromptChan <- task
		}
	}
}

// cleanupEntities removes aliases that are not present in the config
func (ident *IdentitySecretsEngine) cleanupAliases() {
	ident._cleanupAliases("entity", ident.entityAliases, ident.existingEntityAliases)
	ident._cleanupAliases("group", ident.groupAliases, ident.existingGroupAliases)
}

func (ident *IdentitySecretsEngine) _cleanupAliases(aliasType string, aliasList map[string]map[string]identity.Alias, existingAliasList identity.AliasList) {
	ident.fetchAliases(aliasType, existingAliasList)
	for _, existingAlias := range existingAliasList {
		if _, ok := aliasList[existingAlias.MountAccessor][existingAlias.Name]; ok {
			log.Debugf("Identity %s alias [%s/%s] exists in configuration, no cleanup necessary", aliasType, existingAlias.MountAccessor, existingAlias.Name)
		} else {
			// Don't delete alias if it belongs to an entity prefixed with entity_
			// These aliases are created automatically and it cannot be known if
			// these are valid or not
			if aliasType == "entity" {
				entity := ident.existingEntities.GetEntityByID(existingAlias.CanonicalID)
				if entity != nil && strings.HasPrefix(entity.Name, "entity_") {
					continue
				}
			}

			task := taskDelete{
				Description: fmt.Sprintf("Identity %s alias [%s/%s]", aliasType, existingAlias.MountAccessor, existingAlias.Name),
				Path:        path.Join(ident.MountPath, fmt.Sprintf("%s-alias/id", aliasType), existingAlias.ID),
			}
			taskPromptChan <- task
		}
	}
}

func (ident *IdentitySecretsEngine) fetchAuthMounts() {
	authList, err := VaultSys.ListAuth()
	if err != nil {
		log.Fatalf("Unable to list auth mounts: %v", err)
	}

	jsondata, err := json.Marshal(authList)
	if err != nil {
		log.Fatalf("Unable to marshall auth mounts: %v", err)
	}

	ident.authMounts = make(map[string]auth.Mount)
	if err := json.Unmarshal(jsondata, &ident.authMounts); err != nil {
		log.Fatalf("Unable to unmarshall auth mounts: %v", err)
	}
}
