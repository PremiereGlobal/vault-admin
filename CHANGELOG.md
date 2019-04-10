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
