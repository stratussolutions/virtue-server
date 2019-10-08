package kube

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	kubeconfig = flag.String("kubeconfig", "kubeconfig.txt", "absolute path to the kubeconfig file")
)

type UnstructuredResource struct {
	name      string
	namespace string
	obj       *unstructured.Unstructured
	path      string
}

// CreateUserPVC will create the user Persistant Volume Claim.
func CreateUserPVC(dir string, user string) {
	filename := dir + "/" + user + "_pvc.json"
	fmt.Printf("Creating PVC for %s from source %s\n", user, filename)
	from, err := os.Open(dir + "/template_pvc.json")
	if err != nil {
		log.Fatal(err)
	}
	defer from.Close()

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

	DeployVirtue(filename, "create")
}

func DeployVirtue(path string, action string) {
	exe := "kubectl"

	if runtime.GOOS == "windows" {
		exe = "C:/Program Files/Git/usr/bin/ssh-keygen.exe"
	}
	progArgs := []string{action, "-f", path}
	command := exec.Command(exe, progArgs...)
	out, execErr := command.Output()
	//fmt.Printf("Executing Kubernetes command %+v\n", command)

	if execErr != nil {
		fmt.Printf("Error deploying virtue at path %+v with action %+v. Error: %+v\n", path, action, execErr)
	}

	fmt.Printf("Deployed virtue %+v. Result from kubectl %+v: %+v\n", path, action, string(out))

	//We ignore errors since kubectl sometimes outputs exit status 1, but doesn't seem to impact anything
	//check(execErr)

	/*content, readErr := ioutil.ReadFile(path)
	check(readErr)
	kibernits := &unstructured.Unstructured{}
	ume := json.Unmarshal(content, kibernits)
	check(ume)
	resource := &meta_v1.APIResource{Name: virtueName, Namespaced: false}
	gv := schema.GroupVersion{Group: "foo.bar.com", Version: "v2beta1"}
	cl, err := dynamic.NewClient(&restclient.Config{
		Host:          config.KubernetesAPI,
		ContentConfig: restclient.ContentConfig{GroupVersion: &gv},
	})
	got, err := cl.Resource(resource, "default").Create(kibernits)

	if err != nil {
		t.Errorf("unexpected error when creating %q: %v", tc.name, err)
		continue
	}*/
}

//GetServiceNodePort Get the port that the Windows workspace client connects to.
func GetServiceNodePort(clientset *kubernetes.Clientset, serviceName string) (int32, error) {
	service, err := clientset.Core().Services("default").Get(serviceName, meta_v1.GetOptions{})
	if err != nil {
		return -1, err
	}
	for p := range service.Spec.Ports {
		fmt.Println("NodePort:", service.Spec.Ports[p].NodePort)
		return service.Spec.Ports[p].NodePort, nil
	}
	return -1, nil
}

func GetKubernetesClient() *kubernetes.Clientset {
	flag.Parse()
	// uses the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	return clientset
}
