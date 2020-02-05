## 0.4.0

IMPROVEMENTS:
* Added concurrency.  By default, `vault-admin` will use 5 "threads" to process config items.  This count can be configured with the `-n`/`--concurrent` command line flags.
  * Note: Concurrency changes the order of operations for some actions. This should not pose any problems but any user prompts will now be held off until the end of the run.
* Reduced logging verbosity for default level

## 0.3.1

BUGFIXES:
* Fixed issue where kv backends not at the default `secret/` path would prompt to delete.  Also fixed potential issue for `cubbyhole` `system` and `identity` backends not at their default paths.

## 0.3.0

FEATURES:
* Added `--rotate-creds` flag for rotating secret engine credentials (currently just AWS supported)

IMPROVEMENTS:
* Added top-level `overwrite_root_config` parameter for AWS secret backend configs `aws.json`.  This will force an overwrite of the root config.  The default behavior will be to leave the root credentials alone if the mount already exists.  This will allow AWS keys to be rotated.

## 0.2.0

FEATURE:
* Added string substitution for auth methods

## 0.1.0

**BREAKING CHANGES:**
* The format of `auth_methods` has changed slightly to allow for a more generic configuration for all auth types.  The  `auth_options` and `config` top-level keys have not changed but all additional config has been brought down a level into the `additional_config` section. See the [auth_method examples](examples/auth_method) for details.

```
{
  "auth_options": {
    ...
  },
  "config": {
    ...
  },
  "additional_config": {
    "policy_map": {
      ...
    }
  }
}
```

FEATURES:
* Userpass Auth method now supported. See [examples](examples/) for syntax.
* Identity Entities, EntityAliases and Groups are now supported.  See [examples](examples/) for syntax.
* Added more extensive debug logging

FIXED:
* Issue where debug logging would expose the Vault token being used
* Infinite loop when prompting if a non-interactive terminal is being used

## 0.0.6

FIXED:
* Issue with AWS secret backend when setting a role using `policy_arns` without a `raw_policy` or `policy_document` where the role would end up in a bad state

OTHER:
* Refactored to use go modules (go 1.12)

## 0.0.5

**BREAKING CHANGES:**
* Due to the addition of policy ARNs in AWS secret backend roles, the format of the role configs have changed.  Policies using raw definitions must now be specified like so:

```
{
  "credential_type": "iam_user",
  "raw_policy": {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
  }
}
```

IMPROVEMENTS:
* AWS secrets engine roles can now be configured with policy arns as well as raw policy docs
* Fixed fatal errors when certain configs didn't exist (audit_methods, secrets_engines, etc.)

OTHER:
* Added some testing scripts

## 0.0.4

FEATURES:

* Added ability to update mount description (for Auth and Secrets Engines) [#1]
* Added ability to change `listing_visibility` for mounts (Auth and Secrets Engines) [#2]

IMPROVEMENTS:

* Added documentation in [examples/](examples/) for details on setting up the configuration files [#3]

OTHER:

* Bumped API version to Vault 0.11.1
* Using `dep` for vendor management

## 0.0.3

FEATURES:

 * Added [Audit Devices](https://www.vaultproject.io/docs/audit/index.html) as a configuration option

IMPROVEMENTS:

* Better log messaging
