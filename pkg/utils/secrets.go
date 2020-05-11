package utils

func getSecretList(path string) (bool, []string) {

	var secretArray []string

	// Read secrets from Vault for substitution
	secret, err := Vault.List(path)
	if err != nil {
		log.Fatal(err)
	}

	if secret != nil {
		for _, v := range secret.Data {
			switch value := v.(type) {
			case []interface{}:
				for _, k := range value {
					switch key := k.(type) {
					case string:
						secretArray = append(secretArray, string(key))
					default:
						log.Fatal("Issue parsing Vault secret list [" + path + "] [error 001]")
					}
				}
			default:
				log.Fatal("Issue parsing Vault secret list [" + path + "] [error 002]")
			}
		}
	} else {
		return false, nil
	}

	return true, secretArray
}
