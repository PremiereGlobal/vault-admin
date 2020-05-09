# Identity Configuration

## Entities
Identity entity configuration should be placed in the `${CONFIGURATION_PATH}/secrets-engines/identity/entities` directory.  Each file in this directory will create/update an entity with the same name as the file name.

Entity configurations takes the form of:
```
{
  "entity": <entityConfig>
  "entity-aliases": <[]entityAliasConfig>
  "entity-groups": <[]entityGroups>
}
```

### `<entityConfig>`
Contains the definition of the entity and takes a similar form as the [Create an Entity](https://www.vaultproject.io/api-docs/secret/identity/entity#create-an-entity) api call.  Valid fields are `type`, `metadata`, and `policies`.  Other entity configurations (such as `id` and `name`) are managed automatically.  For example:
```
  "entity": {
    "metadata": {
      "organization": "hashicorp",
      "team": "vault"
    },
    "policies": [
      "eng-dev",
      "infra-dev"
    ],
    "disabled": false
  }
```

### `<[]entityAliasConfig>`
Contains a list of definitions of [entity aliases](https://www.vaultproject.io/docs/secrets/identity#entities-and-aliases) to associate with this entity.  Takes a similar form as the [Create an Entity Alias](https://www.vaultproject.io/api-docs/secret/identity/entity-alias#create-an-entity-alias) api call but without the `id` or `canonical_id` attributes (these will be added automatically using the ids of the entity/alias).  Also, in order to make mounting easier, `mount_accessor` can be replaced with `mount_path` to specify the mount to which the alias should belong to.   For example:
```
  "entity-aliases": [
    {
      "name": "testuser",
      "mount_accessor": "auth_userpass_e50b1a44"
    },
    {
      "name": "testuser21",
      "mount_accessor": "auth_github_a50f1a24"
    }  
  ]
```
OR
```
  "entity-aliases": [
    {
      "name": "testuser",
      "mount_accessor": "userpass/"
    },
    {
      "name": "testuser21",
      "mount_accessor": "github/"
    }
  ]
```

### `<[]entityGroups>`
Contains a list of identity group names to associate with this entity. For example:
```
  "entity-groups": [
    "team-a",
    "developers",
    "denver"
  ]
```

## Groups
Identity group configuration should be placed in the `${CONFIGURATION_PATH}/secrets-engines/identity/groups` directory.  Each file in this directory will create/update a group with the same name as the file name.

Group configurations takes the form of:
```
{
  "group": <groupConfig>
  "group-aliases": <groupAliasConfig>
  "group-groups": <[]groupGroups>
}
```

### `<groupConfig>`
Contains the definition of the group and takes a similar form as the [Create an Group](https://www.vaultproject.io/api-docs/secret/identity/group#create-a-group) api call.  Valid fields are `type`, `metadata`, and `policies`.  Group membership is managed either via the entity configuration (see above) or via the group-groups configuration (see below).
```
  "group": {
    "type": "internal",
    "metadata": {
      "hello": "world"
    },
    "policies": [
      "group-policy-1",
      "group-policy-2"
    ]
  }
```

### `<[]groupAliasConfig>`
> Note: Group aliases only work on groups of type: *external*

Contains a single of definitions of a [group alias](https://www.vaultproject.io/docs/secrets/identity#external-vs-internal-groups) to associate with this group.   Takes a similar form as the [Create a Group Alias](https://www.vaultproject.io/api-docs/secret/identity/group-alias#create-a-group-alias) api call but without the `id` or `canonical_id` attributes (these will be added automatically using the ids of the group/alias).  Also, in order to make mounting easier, `mount_accessor` can be replaced with `mount_path` to specify the mount to which the alias should belong to.   For example:
```
  "group-alias": {
    "name": "sre",
    "mount_accessor": "auth_github_e50b1a44"
  }
```
OR
```
  "group-alias": {
    "name": "sre",
    "mount_path": "github/"
  }
```

### `[]<groupGroups>`
Contains a list of identity parent group names to which this group should belong. For example:
```
  "entity-groups": [
    "team-a",
    "developers",
    "denver"
  ]
```

## Examples
Examples can be found in [examples/secrets-engines/identity](../../examples/secrets-engines/identity).
