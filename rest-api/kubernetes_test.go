package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	core "virtue_cli/core/shared"
)

/*func TestKubernetes(t *testing.T) {
	clientset := GetKubernetesClient()
	port := GetServiceNodePort(clientset, "internet-kamoser-leafpad-service")
	assert.Equal(t, port, int32(30390))
}*/

type User struct {
	Username string `json:"username"`
}

func TestMain(t *testing.T) {
	user := new(User)
	user.Username = "anything"

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(user)

	//Ignore the credentials. The user workspace registers it's own token so it makes NO SENSE
	//to "login" the user from a command line application, when they are really logging in
	//from their Windows workspace. Furthermore, just return the user's actual workspace token
	//as long as the username exists and completely ignore the credentials.
	response, err := http.Post(url+"/cli_logon", "application/json; charset=utf-8", b)
	if err != nil {
		fmt.Printf("")
	}

	token := &core.UserToken{}
	core.ParseJSON(response, token)
	//fmt.Printf("Response: %+v\n", token)
	if token.Token == "" {
		return 13
	}

	return 0
}
