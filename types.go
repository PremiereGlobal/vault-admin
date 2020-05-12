package main

type SecretList []string

func (secretList *SecretList) Add(item string) {
	*secretList = append(*secretList, item)
}

func (secretList SecretList) Contains(needle string) bool {
	for _, item := range secretList {
		if item == needle {
			return true
		}
	}
	return false
}
