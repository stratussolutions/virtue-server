package kube

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
)

func TestCreateUserPVC(t *testing.T) {
	user := "dabryan"
	dir := "C:\\Users\\Dan Bryan\\.code\\virtue_kube\\pvcs"

	fmt.Printf("Creating PVC for %+v", user)
	from, err := os.Open(dir + "/template_pvc.json")
	if err != nil {
		log.Fatal(err)
	}
	defer from.Close()
	filename := dir + "/" + user + "_pvc.json"
	to, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	if err != nil {
		log.Fatal(err)
	}
	input, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalln(err)
	}

	lines := strings.Split(string(input), "\n")

	for i, line := range lines {
		if strings.Contains(line, "template-data-volume") {
			lines[i] = `                "name": "` + user + `-data-volume",`
		}
	}
	output := strings.Join(lines, "\n")
	err = ioutil.WriteFile(filename, []byte(output), 0644)
	if err != nil {
		log.Fatalln(err)
	}
}
