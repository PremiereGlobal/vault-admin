package main

import (
  "os"
  "fmt"
  "reflect"
  log "github.com/Sirupsen/logrus"
  envconfig "github.com/kelseyhightower/envconfig"
  VaultApi "github.com/hashicorp/vault/api"
  GoFlags "github.com/jessevdk/go-flags"
)

// Application options
type Specification struct {
  ConfigurationPath string `vrequired:"true" envconfig:"CONFIGURATION_PATH" short:"c" long:"configuration-path" description:"Path to the configuration files"`
  VaultAddress  string `vrequired:"true" envconfig:"VAULT_ADDR" short:"a" long:"vault-addr" description:"Vault address (ex: https://vault.mysite.com:8200)"`
  VaultToken    string `envconfig:"VAULT_TOKEN" short:"t" long:"vault-token" description:"Vault token to use, otherwise will prompt for LDAP credentials"`
  VaultSkipVerify bool `envconfig:"VAULT_SKIP_VERIFY" short:"K" long:"skip-verify" description:"Skip Vault TLS certificate verification"`
  VaultSecretBasePath string `envconfig:"VAULT_SECRET_BASE_PATH" short:"s" long:"vault-secret-base-path" description:"Base secret path, in Vault, to pull secrets for substitution" vdefault:"secret/vault-admin/"`
  Debug bool `envconfig:"DEBUG" short:"d" long:"debug" description:"Turn on debug logging"`
  Version bool `short:"v" long:"version" description:"Display the version of the tool"`
  CurrentVersion string
}

var version string
var VaultClient *VaultApi.Client
var Vault *VaultApi.Logical
var VaultSys *VaultApi.Sys
var Spec Specification

func main() {

  // If version is set during build, use that
  if(version != "") {
    Spec.CurrentVersion = version
  } else {
    Spec.CurrentVersion = "dev"
  }

  // General-use error handlers
  var err error

  // Parse command line arguments first
  var options GoFlags.Options
  options = GoFlags.HelpFlag | GoFlags.PassDoubleDash
  argParser := GoFlags.NewParser(&Spec, options)
  retArgs, err := argParser.ParseArgs(os.Args)
  if err != nil {
    if(len(retArgs) > 0) {
      log.Fatal(fmt.Sprintf("%+v", err.Error()))
    } else {
      fmt.Println(err)
      os.Exit(0)
    }
  }

  // If getting version, do that and exit
  if(Spec.Version) {
    fmt.Println("Vault Admin version: " + Spec.CurrentVersion)
    return
  }

  // Parse environment variables
  err = envconfig.Process("", &Spec)
  if err != nil {
      log.Fatal(err.Error())
  }

  // 75f4fc2a-4655-54a3-0605-7791a781aa14
  // Set log level
  if Spec.Debug {
    log.SetLevel(log.DebugLevel)
    log.Debug("Debug level set")
  } else {
    log.SetLevel(log.InfoLevel)
  }

  // Set defaults and ensure required vars are set
  // We're using custom functions for this because we're using two separate libraries for reading in configuration (args/envs)
  setDefault(&Spec)
  checkRequired(&Spec)

  // Print Spec configuration if debugging
  log.Debug(fmt.Sprintf("%+v", Spec))

  // Configure new Vault Client
  conf := &VaultApi.Config{Address: Spec.VaultAddress}
  tlsConf := &VaultApi.TLSConfig{Insecure: Spec.VaultSkipVerify}
  conf.ConfigureTLS(tlsConf)
  VaultClient, _ = VaultApi.NewClient(conf)
  VaultClient.SetToken(Spec.VaultToken)

  // Define a Logical Vault client (to read/write values)
  Vault = VaultClient.Logical()
  VaultSys = VaultClient.Sys()

  // Ensure we can connect to the Vault api
  health, err := VaultSys.Health()
  if err != nil {
    log.Fatal("Error connecting to Vault: ", err)
  }
  log.Debug("Initialized: ", health.Initialized)
  log.Debug("Sealed: ", health.Sealed)
  log.Debug("Standby: ", health.Standby)
  log.Debug("Version: ", health.Version)

  // Call sync methods
  SyncAuthMounts()
  SyncPolicies()
  SyncSecretsEngines()

  log.Debug("Done")
}


func setDefault(spec *Specification) {

  t := reflect.TypeOf(*spec)

  for i := 0; i < t.NumField(); i++ {

    // Get the field, returns https://golang.org/pkg/reflect/#StructField
    field := t.Field(i)

    // Get the field tag value
    tag := field.Tag.Get("vdefault")

    r := reflect.ValueOf(spec)
    fieldValue := reflect.Indirect(r).FieldByName(field.Name)
    if(tag != "" && fieldValue.String() == "") {
      log.Debug("No value for " + field.Name + " set. Setting to default: " + tag)
      fieldValue.SetString(tag)
    }
  }
}

func checkRequired(spec *Specification) {

  t := reflect.TypeOf(*spec)

  for i := 0; i < t.NumField(); i++ {

    // Get the field, returns https://golang.org/pkg/reflect/#StructField
    field := t.Field(i)

    // Get the field tag value
    tag := field.Tag.Get("vrequired")

    if(tag == "true" && field.Type.Name() != "bool") {
      r := reflect.ValueOf(spec)
      fieldValue := reflect.Indirect(r).FieldByName(field.Name)
      if(fieldValue.String() == "") {
        log.Fatal(field.Name + " required but not set. Use environment variable " + field.Tag.Get("envconfig") + " or command line options: --" + field.Tag.Get("long") + ", -" + field.Tag.Get("short"))
      }
    }
  }
}
