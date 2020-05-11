package main

type SecretList []string

func (secretList SecretList) Contains(needle string) bool {
	for _, item := range secretList {
		if item == needle {
			return true
		}
	}
	return false
}
