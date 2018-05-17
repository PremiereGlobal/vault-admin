# Vault Admin [![Build Status](https://travis-ci.org/ReadyTalk/vault-admin.svg?branch=master)](https://travis-ci.org/ReadyTalk/vault-admin)

This utility configures Vault audit devices, auth methods, policies and secrets engines by syncing with a set of standard JSON configuration files.

- [Installation](#installation)
	- [CLI](#cli)
	- [Docker](#docker)
- [Options](#options)
- [Configuration Files](#configuration-files)

## Installation

This utility can be used via Docker or the CLI.

### CLI
Download and extract the latest binary for your OS on the [releases page](https://github.com/ReadyTalk/vault-admin/releases)

Run `./vadmin <flags>`.  See below for a description of the command line flags.

### Docker
The Docker container must be run in interactive mode with the `-it` because it prompts for things like policy deletion, etc.

```
docker run \
  --rm \
	-it \
	-e VAULT_ADDR=https://vault.mysite.com:8200 \
	-e VAULT_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
	-v $(pwd)/config:/config
	readytalk/vault-admin:latest
```

Map wherever you have your Vault configuration files to `/config` within the container.

## Options
All options can be set via environment variables or command line options

| Environment Variable               | Command Line Flags | Description                           |
| ----------------------- | ----------------------------------    | ---------------------------------------------------------- |
| `CONFIGURATION_PATH` | --configuration-path, -c | Path to the configuration files |
| `VAULT_ADDR` | --vault-addr, -a | Vault address (example: https://vault.mysite.com:8200) |
| `VAULT_TOKEN` | --vault-token, -t | Vault token to use |
| `VAULT_SKIP_VERIFY` | --vault-skip-verify, -K | Skip Vault TLS certificate verification |
| `VAULT_SECRET_BASE_PATH`  | --vault-secret-base-path, -s | Base secret path, in Vault, to pull secrets for substitution. Defaults to `secret/vault-admin` |
| `DEBUG`  | --debug, -d | Turn on debug logging |

## Configuration Files
The configuration files are what drive how Vault is configured.  The following is an example of how to set up your `CONFIGURATION_PATH`.  See the [examples/](examples/) directory for how these files should be structured.

```bash
├── audit_devices/
│   └── stdout.json
├── auth_methods/
│   ├── github.json
│   ├── ldap.json
│   └── ldap-2.json
├── policies/
│   ├── back-end-team.json
│   ├── billing.json
│   ├── ci-team.json
│   ├── front-end-team.json
│   └── sre-team.json
├── secrets-engines/
│   ├── aws-main/
│   │   ├── aws.json
│   │   ├── config.json
│   │   ├── roles/
│   │   │   ├── admin.json
│   │   │   ├── s3-read-only.json
│   │   │   ├── s3-read-write.json
│   │   │   └── sqs.json
│   ├── aws-sandbox/
│   │   └── ...
│   ├── db-dev/
│   │   ├── db.json
│   │   ├── config.json
│   │   ├── roles/
│   │   │   ├── admin.json
│   │   │   ├── read-only.json
│   │   │   └── read-write.json
│   ├── db-prod/
│   │   └── ...
```
