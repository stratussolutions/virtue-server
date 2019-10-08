package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	virtue_kube "virtue_cc/kube"

	"virtue_cc/env"

	"github.com/gorilla/mux"
	"k8s.io/client-go/kubernetes"
)

var err error
var config *env.Info
var userMap map[string]string
var windowsConfig *WindowsConfiguration

//RemoteApp Configuration to set up a remote desktop connection broker and remote desktop session host.
//The RDCB is always the same machine, the RDSH varies based on where the user's applications are deployed.
//A single Virtue can map to multiple RemoteApp objects, but the RDSH will be the same whereas the collection,
//display name, and file path will differ based on whatever application is being made available.
type RemoteApp struct {
	SessionHostDeployed bool   `json:"session_host_deployed,omitempty"`
	ConnBrokerDeployed  bool   `json:"connection_broker_deployed,omitempty"`
	VirtueName          string `json:"virtue,omitempty"`
	DisplayName         string `json:"display_name,omitempty"`
	CollectionName      string `json:"collection_name,omitempty"`
	UserGroup           string `json:"user_group,omitempty"`
	Username            string `json:"username,omitempty"`
	FilePath            string `json:"path,omitempty"`
	SessionHost         string `json:"session_host,omitempty"`
	ConnectionBroker    string `json:"connection_broker,omitempty"`
	ID                  int    `json:"id,omitempty"`
}

type SessionHost struct {
	Hostname string `json:"hostname,omitempty"`
	Token    string `json:"token,omitempty"`
}

type WindowsConfiguration struct {
	Virtues                       []*RemoteApp  `json:"remoteapps,omitempty"`
	SessionHosts                  []SessionHost `json:"session_hosts,omitempty"`
	RemoteDesktopConnectionBroker string        `json:"rdcb"` //RDCB for remoteapp configs
	LastID                        int           `json:"last_id"`
}

func WriteJSON(val interface{}, path string) {
	result, err := json.Marshal(val)
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		err = ioutil.WriteFile(path, result, 0644)
		if err != nil {
			fmt.Printf("%+v\n", err)
		}
	}
}

func ReadJSON(val *WindowsConfiguration, path string) {
	result, err := ioutil.ReadFile(path)
	err = json.Unmarshal(result, val)
	if err != nil {
		fmt.Printf("%+v\n", err)
	} else {
		fmt.Printf("JSON read from file: %+v\n", val)
	}
}

func WriteWindowsConfiguration(val interface{}, path string) {
	ticker := time.NewTicker(time.Minute * 1)
	for range ticker.C {
		fmt.Printf("JSON write to file: %+v\n", val)
		WriteJSON(val, path)
	}
}

func main() {
	userMap = make(map[string]string)
	windowsConfig = &WindowsConfiguration{}
	config, err = env.LoadConfig("config.json")
	ReadJSON(windowsConfig, config.WindowsVirtueConfig)
	fmt.Printf("Loaded the windows configuration: %+v\n", windowsConfig)
	//Launch a thread to periodically write the config back to disk
	go WriteWindowsConfiguration(windowsConfig, config.WindowsVirtueConfig)

	if err != nil {
		fmt.Printf("Error loading config for virtue REST API, %+v\n", err)
		return
	}

	fmt.Printf("User virtue configuration (deployments) are in the directory %+v\n", config.VirtueConfiguration.VirtueDirectory)
	router := mux.NewRouter()

	router.HandleFunc("/remoteapp", GetRemoteAppConfig).Methods("POST")
	router.HandleFunc("/config", GetVirtues).Methods("POST")
	router.HandleFunc("/addrdsh", AddRemoteAppHost).Methods("POST")
	router.HandleFunc("/register", Register).Methods("POST")
	router.HandleFunc("/publickey", PublicKey).Methods("POST")
	router.HandleFunc("/privatekey", PrivateKey).Methods("POST")
	router.HandleFunc("/logoff", Logoff).Methods("POST")
	router.HandleFunc("/logon", Logon).Methods("POST")
	router.HandleFunc("/cli_logon", GetUserToken).Methods("POST")
	router.HandleFunc("/getvirtue", GetVirtueById).Methods("POST")

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
	}
	srv := &http.Server{
		Addr:         ":443",
		Handler:      router,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}

//VirtueApplication represents a single app that's part of a virtue/role
/*
[dev-dan-firefox]
name=dev-dan-firefox
icon=:/img/icons/128x128/x2gosession.png
host=a91268b5ffb9f11e79c6c02a410e2607-1951916279.us-east-1.elb.amazonaws.com
key=D:/Users/dan/Documents/ppk/bryanlabs-aws.key
sshport=22
command=firefox
applications=firefox
*/
type VirtueApplication struct {
	VirtueIconURL string `json:"icon,omitempty"`
	VirtueName    string `json:"virtue,omitempty"`
	Application   string `json:"application,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	Port          string `json:"port,omitempty"`
	Command       string `json:"command,omitempty"`
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func GetVirtueById(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	iid, err := strconv.Atoi(id)
	if err != nil {
		json.NewEncoder(w).Encode("No virtue with that ID")
	}

	for _, virtue := range windowsConfig.Virtues {
		if virtue.ID == iid {
			json.NewEncoder(w).Encode(virtue)
		}
	}

	return
}

//AddRemoteAppHost Add a new configuration that will be deployed to an available
//remote desktop session host (or whichever one is specified)
func AddRemoteAppHost(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Attempting to add a new remoteapp config.\n")
	app := &RemoteApp{}
	virtueName := r.PostFormValue("virtue")
	displayName := r.PostFormValue("display")
	collectionName := r.PostFormValue("collection")
	userName := r.PostFormValue("username")
	filePath := r.PostFormValue("applicationPath")
	sessionHost := r.PostFormValue("rdsh")
	app.CollectionName = collectionName
	app.ConnBrokerDeployed = false
	app.ConnectionBroker = windowsConfig.RemoteDesktopConnectionBroker
	app.DisplayName = displayName
	app.FilePath = filePath
	windowsConfig.LastID++
	app.ID = windowsConfig.LastID
	app.SessionHost = sessionHost
	app.SessionHostDeployed = false
	app.UserGroup = config.WindowsDomainName + "\\" + userName
	app.Username = userName
	app.VirtueName = virtueName

	windowsConfig.Virtues = append(windowsConfig.Virtues, app)
	fmt.Printf("Added the following remoteapp config: %+v\n", app)
	json.NewEncoder(w).Encode(app)
}

//PublicKey get the public key from the user workspace
func PublicKey(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Public key function called.\n")
	userIdentityToken := r.PostFormValue("token")
	username := userMap[userIdentityToken]

	if username != "" {
		fmt.Printf("User public key: %+v", r.PostFormValue("key"))
		filePath := config.VirtueConfiguration.TempPublicKeyDirectory + "/" + username + ".pub"
		f, ferr := os.Create(filePath)
		check(ferr)
		f.WriteString(r.PostFormValue("key"))
		f.Sync()
		f.Close()

		ConvertPublicKeysToOpenSSH(filePath, username)
		json.NewEncoder(w).Encode("we got your public keys...")
	}
}

//ConvertPublicKeysToOpenSSH converts keys to open-ssh format so they can be used in SSH connections
func ConvertPublicKeysToOpenSSH(filePath string, username string) {
	fmt.Printf("Convert public key to open ssh function called.\n")
	exe := "ssh-keygen"

	if runtime.GOOS == "windows" {
		exe = "C:/Program Files/Git/usr/bin/ssh-keygen.exe"
	}

	progArgs := []string{"-f", filePath, "-i", "-m", "PKCS8"}
	openSSHPath := config.VirtueConfiguration.PublicKeyDirectory + "/" + username + ".pub"
	fmt.Printf("OpenSSH path is %+v\n", openSSHPath)
	out, execErr := exec.Command(exe, progArgs...).Output()
	check(execErr)
	f, ferr := os.Create(openSSHPath)
	check(ferr)
	defer f.Close()
	f.Write(out)
	f.Sync()
}

//PrivateKey get the private key from the user workspace, this should ONLY be used for testing
func PrivateKey(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("User private key: %+v", r.PostFormValue("key"))
	json.NewEncoder(w).Encode("we got your private keys...")
}

func Logon(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("User logged on, making sure virtues are created.")
	GetVirtues(w, r)
}

type User struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

func GetUserToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	//fmt.Printf("Test: %v", r.Form)
	//fmt.Printf("get user token post values: %+v\n", r.PostForm)
	//fmt.Printf("Post Form: %+v\n", r.Form)
	//r.ParseForm()
	fmt.Println("USER: ", r.PostFormValue("username"))
	var u User
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		fmt.Printf("Decode error:", err.Error())
	}
	fmt.Printf("user yay!: %+v\n", u)

	for k, v := range userMap {
		fmt.Printf("current user: %+v\n", v)
		if v == u.Username {
			u.Token = k
			break
		}
	}

	json.NewEncoder(w).Encode(u)
	return
}

func RegisterInfrastructure(token string, host string) bool {
	fmt.Printf("Attempting to register the token %+v to the host %+v\n", token, host)
	register := true
	existingMatch := false

	if token == "" || host == "" {
		fmt.Printf("Invalid token or host\n")
		return false
	}

	for _, v := range windowsConfig.SessionHosts {
		if v.Hostname == host {
			register = false
		}
		if v.Token == token && v.Hostname == host {
			existingMatch = true
			register = false
		}
	}

	if register {
		sessionHost := &SessionHost{Token: token, Hostname: host}
		windowsConfig.SessionHosts = append(windowsConfig.SessionHosts, *sessionHost)
		fmt.Printf("Registered the token %+v to the host %+v\n", token, host)
	} else if !existingMatch {
		fmt.Printf("Failed to register the token %+v to the host %+v\n", token, host)
	} else if existingMatch {
		fmt.Printf("The token %+v is already registered to the host %+v\n", token, host)
	} else {
		fmt.Printf("Unknown error. Token %+v and host %+v\n", token, host)
	}

	return register || existingMatch
}

func Register(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("User attempting token registration.\n")
	userToken := r.PostFormValue("token")
	user := r.PostFormValue("user")
	//Creates the persistant volume claim for the new user.
	pvcdir := config.VirtueConfiguration.PVCDirectory
	fmt.Printf("PVCDIR: %v\n", pvcdir)
	fmt.Printf("USER: %v\n", user)
	virtue_kube.CreateUserPVC(pvcdir, user)
	fmt.Printf("Attempting to register the token %+v to the user %+v\n", userToken, user)
	register := true

	for _, v := range userMap {
		if v == user {
			register = false
		}
	}

	if register {
		userMap[userToken] = user
		fmt.Printf("Registered the token %+v to the user %+v\n", userToken, user)
	} else {
		fmt.Printf("Failed to register the token %+v to the user %+v\n", userToken, user)
	}

	json.NewEncoder(w).Encode("Done")
}

func Logoff(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Destroying user resources (virtues)")
	fmt.Print(ioutil.ReadAll(r.Body))
	userIdentityToken := r.PostFormValue("token")
	username := userMap[userIdentityToken]
	virtues := GetVirtueSkeletonList(username)
	for _, path := range virtues {
		virtue_kube.DeployVirtue(path, "delete")
	}

	fmt.Printf("Processed logoff event for client %+v\n", username)
	json.NewEncoder(w).Encode("Received logoff event for client " + username)
}

func EnsureDir(path string) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(path, os.ModePerm)
		}
	}
}

//GetVirtueSkeletonList Get the list of Kubernetes YAML files for this user.
func GetVirtueSkeletonList(username string) []string {
	userVirtueDirectory := config.VirtueConfiguration.VirtueDirectory + "/" + username
	EnsureDir(userVirtueDirectory)
	fmt.Printf("User virtue skeletons are in the directory %+v\n", userVirtueDirectory)

	fileList := []string{}
	walkErr := filepath.Walk(userVirtueDirectory, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})

	check(walkErr)
	for _, file := range fileList {
		fmt.Println(file)
	}

	return fileList
}

func ConvertFilenameToVirtue(filename string) string {
	idx := strings.LastIndex(filename, "-")
	virtueName := filename[:idx]
	fmt.Printf("The virtue name is %+v\n", virtueName)
	return virtueName
}

func EnsureDeployVirtues(kubeClient *kubernetes.Clientset, username string) []string {
	fileList := []string{}
	publicKeyPath := config.VirtueConfiguration.PublicKeyDirectory + "/" + username + ".pub"
	//The public key hasn't been registered so we shouldn't deploy any virtues yet
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return fileList
	}

	userVirtueDirectory := config.VirtueConfiguration.VirtueDirectory + "/" + username
	EnsureDir(userVirtueDirectory)
	fmt.Printf("Checking that all virtues are deployed for directory %+v\n", userVirtueDirectory)

	walkErr := filepath.Walk(userVirtueDirectory, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			fileList = append(fileList, f.Name())
			virtueName := ConvertFilenameToVirtue(f.Name())
			serviceName := GetServiceName(config.VirtueConfiguration.VirtueDirectory + "/" + username + "/" + f.Name())
			_, serviceErr := virtue_kube.GetServiceNodePort(kubeClient, serviceName)
			if serviceErr != nil {
				fmt.Printf("The virtue %+v is not yet deployed, we will deploy it now. \n", virtueName)
				virtue_kube.DeployVirtue(path, "create")
				_, serviceErr = virtue_kube.GetServiceNodePort(kubeClient, serviceName)
				check(serviceErr)
			}
		}
		return nil
	})

	check(walkErr)
	for _, file := range fileList {
		fmt.Println(file)
	}

	return fileList
}

func GetServiceName(path string) string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "name") {
			results := strings.Split(line, "virt-")
			service := results[1]
			//fmt.Printf("Service before parse: %+v\n", service)
			end := strings.LastIndex(service, "\"")
			//fmt.Printf("Service end index: %+v\n", end)
			fmt.Printf("Service name: '%+v'\n", "virt-"+service[0:end])
			return "virt-" + service[0:end]
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return "invalid-service"
}

//GetVirtues return a list of virtues for the user
func GetVirtues(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Called GetVirtues\n")
	kubeClient := virtue_kube.GetKubernetesClient()
	fmt.Printf("Got Kubernetes client...\n")

	userIdentityToken := r.PostFormValue("token")
	fmt.Printf("Got user identity token %+v...\n", userIdentityToken)
	username := userMap[userIdentityToken]
	virtues := []VirtueApplication{}
	fmt.Printf("Got client user %+v...\n", username)

	if username != "" {
		fmt.Printf("Finding virtue skeletons for the user: %+v\n", username)
		fileList := EnsureDeployVirtues(kubeClient, username)
		for _, v := range fileList {
			virtueName := ConvertFilenameToVirtue(v)
			serviceName := GetServiceName(config.VirtueConfiguration.VirtueDirectory + "/" + username + "/" + v)
			port, _ := virtue_kube.GetServiceNodePort(kubeClient, serviceName)

			parts := strings.Split(virtueName, "-")
			role := parts[0]
			user := parts[2]
			app := parts[3]

			fmt.Printf("------------------------------\n")
			fmt.Printf("Kubernetes virtue name: %+v\n", virtueName)
			fmt.Printf("Kubernetes node port: %+v\n", port)
			fmt.Printf("Virtue role name: %+v\n", role)
			fmt.Printf("Virtue app name: %+v\n", app)
			fmt.Printf("User name from virtue skeleton: %+v\n", user)
			fmt.Printf("------------------------------\n")

			if username != user {
				fmt.Printf("User %+v obtained from the virtue skeleton is not the same as the username %+v from the windows service.\n", user, username)
			}

			virtues = append(virtues, VirtueApplication{VirtueName: virtueName, Application: app, Hostname: config.VirtueConfiguration.Hostname, Port: fmt.Sprint(port), Command: app})
		}

		json.NewEncoder(w).Encode(virtues)
	}

}

//GetRemoteAppConfig Get the Powershell scripts to execute on the given host.
//RemoteApp configurations are accomplished through a series of Powershell commands.
//Each configuration has a unique identifier which is stored in memory until the
//configuration has been fully deployed. Once the configuration is fully deployed,
//the configuration is written to disk. Each configuration maps 1:1 with the Windows
//applications in a Virtue.
func GetRemoteAppConfig(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Testing remoteapp config...\n")
	token := r.PostFormValue("token")
	host := r.PostFormValue("host")
	fmt.Printf("Getting remoteapp config for token/host pair %+v and %+v. \n", token, host)
	isBroker := host == windowsConfig.RemoteDesktopConnectionBroker
	fmt.Printf("Remote desktop connection broker: %+v\n", windowsConfig.RemoteDesktopConnectionBroker)

	isValidToken := RegisterInfrastructure(token, host)
	if !isValidToken {
		fmt.Printf("Invalid token/host pair %+v and %+v. \n", token, host)
		http.Error(w, "You are not authorized", http.StatusForbidden)
		return
	}
	apps := []*RemoteApp{}
	configuredVirtues := &windowsConfig.Virtues
	fmt.Printf("Looking at known virtues %+v\n", configuredVirtues)

	for _, v := range *configuredVirtues {
		//if isBroker {
		//		fmt.Printf("Checking if the remoteapp broker config for %+v is deployed yet.\n", v.ID)
		//	}

		//else {
		//	fmt.Printf("Checking if the remoteapp session host config for %+v is deployed yet.\n", v.ID)
		//}

		if isBroker && !v.ConnBrokerDeployed {
			fmt.Printf("The remoteapp broker config for %+v is NOT deployed yet.\n", v.ID)
			apps = append(apps, v)
		} else if isBroker {
			fmt.Printf("remoteapp broker config for %+v is deployed.\n", v.ID)
		}
		/*
			else if !isBroker && !v.SessionHostDeployed && v.SessionHost == host && v.ConnBrokerDeployed { //conn broker must be deployed first
				fmt.Printf("The remoteapp session host config for %+v is NOT deployed yet.\n", v.ID)
				apps = append(apps, v)
			} else if !isBroker && !v.SessionHostDeployed && v.SessionHost == host {
				fmt.Printf("For %+v, the remoteapp session host is awaiting configuration, but RDCB must be deployed FIRST.\n", v)
			}*/
	}

	if len(apps) == 0 {
		fmt.Printf("There are no apps pending configuration for the host %+v\n", host)
	}

	powershellScripts := make([]string, 0)
	if isBroker && len(apps) > 0 {
		fmt.Printf("Creating scripts for remote desktop connection broker with hostname %+v.\n", host)
		for _, app := range apps {
			firstApp := !IsSessionCollectionDeployed(*configuredVirtues, app.CollectionName)
			fmt.Printf("Set conn broker deployed for %+v\n", app)
			scripts := AppToRdcbPowershell(*app, firstApp)
			powershellScripts = AddAll(powershellScripts, scripts)
			app.ConnBrokerDeployed = true
		}
	}
	/*
		else if len(apps) > 0 {
			fmt.Printf("Creating scripts for remote desktop session host with hostname %+v.\n", host)
			for _, app := range apps {
				app.SessionHostDeployed = true
				fmt.Printf("Set session host deployed for %+v\n", app)
				powershellScripts = append(powershellScripts, AppToRdshPowershell(*app))
			}
		}*/

	json.NewEncoder(w).Encode(powershellScripts)
}

// IsSessionCollectionDeployed Makes a best effort guess whether the session
// collection is deployed. If the app's collection name matches and the RDCB
// is marked as configured, it assumes the session collection is deployed.
func IsSessionCollectionDeployed(apps []*RemoteApp, collection string) bool {
	for _, app := range apps {
		if app.CollectionName == collection && app.ConnBrokerDeployed {
			return true
		}
	}

	return false
}

func AddAll(orig []string, add []string) []string {
	for _, v := range add {
		orig = append(orig, v)
	}

	return orig
}

func AppToRdcbPowershell(app RemoteApp, isFirstApp bool) []string {
	results := []string{}
	result := ""
	if isFirstApp {
		//Session deployment is created with the server manager on RDCB
		//result = fmt.Sprintf("New-RDSessionDeployment -ConnectionBroker \"%s\" -SessionHost \"%s\"", app.ConnectionBroker+"."+config.WindowsDomainName, app.SessionHost+"."+config.WindowsDomainName)
		//results = append(results, result)
		result = fmt.Sprintf("New-RDSessionCollection -PersonalUnmanaged -CollectionName \"%s\" -SessionHost \"%s\" -ConnectionBroker \"%s\"", app.CollectionName, app.SessionHost+"."+config.WindowsDomainName, app.ConnectionBroker+"."+config.WindowsDomainName)
		results = append(results, result)
		result = fmt.Sprintf("Add-RDSessionHost -CollectionName \"%s\" -SessionHost \"%s\"", app.CollectionName, app.SessionHost+"."+config.WindowsDomainName)
		results = append(results, result)
		result = fmt.Sprintf("Set-RDPersonalSessionDesktopAssignment -CollectionName \"%s\" -ConnectionBroker \"%s\" -User \"%s\" -Name \"%s\"", app.CollectionName, app.ConnectionBroker+"."+config.WindowsDomainName, app.UserGroup, app.SessionHost+"."+config.WindowsDomainName)
	}

	results = append(results, result)
	result = AppToRdshPowershell(app)
	results = append(results, result)
	return results
}

func AppToRdshPowershell(app RemoteApp) string {
	return fmt.Sprintf("New-RDRemoteApp -CollectionName \"%s\" -DisplayName \"%s\" -FilePath \"%s\" -UserGroups \"%s\"", app.CollectionName, app.DisplayName, app.FilePath, app.UserGroup)
}
