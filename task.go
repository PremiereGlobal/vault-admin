package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
)

type taskWrite struct {
	Path        string
	Description string
	Data        map[string]interface{}
	// Defer function to run on the completion of the write operation
	Defer func()
}

type taskDelete struct {
	Description string
	Path        string
}

func (t taskWrite) run(workerNum int) bool {
	defer wg.Done()
	if t.Defer != nil {
		defer t.Defer()
	}
	log.Debugf("Writing %s {worker-%d}", t.Description, workerNum)
	_, err := Vault.Write(t.Path, t.Data)
	if err != nil {
		log.Fatalf("Error writing %s: %v", t.Description, err)
		return false
	}

	return true
}

func (t taskDelete) run(workerNum int) bool {
	log.Infof("%s does not exist in configuration, prompting to delete {worker-%d}", t.Description, workerNum)
	if askForConfirmation(fmt.Sprintf("Delete %s [y/n]?: ", t.Description), 3) {
		_, err := Vault.Delete(t.Path)
		if err != nil {
			log.Fatalf("Error deleting %s: %v", t.Description, err)
		}
		log.Infof("%s deleted", t.Description)
	} else {
		log.Infof("Leaving %s even though it is not in config", t.Description)
	}
	return true
}
