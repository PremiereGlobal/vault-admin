package main

// Rotate backend credentials - currently just AWS
func RotateCreds() {
	existing_mounts, _ := VaultSys.ListMounts()
	for path, mount := range existing_mounts {
		if mount.Type == "aws" {
			secret, err := Vault.Write(path+"config/rotate-root", nil)
			if err != nil {
				log.Warn("Cannot rotate ["+path+"] ", err)
			} else {
				log.Info("Rotated key for ["+path+"].  New access key: ", secret.Data["access_key"].(string))
			}
		}
	}
}
