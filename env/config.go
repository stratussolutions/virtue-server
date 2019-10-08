package env

import (
	"encoding/json"

	"github.com/blue-jay/core/jsonconfig"
)

// *****************************************************************************
// Application Settings
// *****************************************************************************

// Info structures the application settings.
type Info struct {
	KubernetesAPI       string `json:"api"`
	VirtueConfiguration `json:"virtues"`
}

// VirtueConfiguration settings for the Virtue REST application
type VirtueConfiguration struct {
	WindowsDomainName      string `json:"domain"`                //windows domain e.g. virtue.local
	WindowsVirtueConfig    string `json:"windows_virtue_config"` //Windows only remoteapp configs
	VirtueDirectory        string `json:"virtue_directory"`      //Linux only x2go configs
	PVCDirectory           string `json:"pvc_directory"`         //Persistant Volume Claims.
	PublicKeyDirectory     string `json:"public_key_directory"`
	TempPublicKeyDirectory string `json:"temp_pkcs8_directory"`
	Hostname               string `json:"hostname"` //This should be a route 53 round robin DNS name
}

// ParseJSON unmarshals bytes to structs
func (c *Info) ParseJSON(b []byte) error {
	return json.Unmarshal(b, &c)
}

// New returns a instance of the application settings.
func New(path string) *Info {
	return &Info{}
}

// LoadConfig reads the configuration file.
func LoadConfig(configFile string) (*Info, error) {
	// Create a new configuration with the path to the file
	config := New(configFile)

	// Load the configuration file
	err := jsonconfig.Load(configFile, config)

	// Return the configuration
	return config, err
}
