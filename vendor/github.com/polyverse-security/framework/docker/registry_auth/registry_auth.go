package registry_auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/cliconfig/configfile"
	"github.com/polyverse-security/framework/wiring"
	"golang.org/x/net/context"
	"io/ioutil"
	"os"
	"strings"
)

const defaultRegistry = "https://index.docker.io/v1/"

func GetPrivilegeFunc() types.RequestPrivilegeFunc {
	return GetPrivilegeFuncForRegistry(defaultRegistry)
}

func GetPrivilegeFuncForImage(image string) types.RequestPrivilegeFunc {
	registry := defaultRegistry

	//split the image into three parts if possible
	fragments := strings.Split(image, "/")
	if len(fragments) == 3 {
		log.WithField("RegistryFragment", fragments[0]).Info("Registry found. Not using default registry.")
		registry = fragments[0] //first fragment is the registry
	}

	if registry == "docker.io" { //Special case
		log.Info("Registry docker.io being resolved as a special case to the default registry URL")
		registry = defaultRegistry
	}

	//Find registry from the image
	return GetPrivilegeFuncForRegistry(registry)
}

func GetPrivilegeFuncForRegistry(registry string) types.RequestPrivilegeFunc {
	if cf, err := getDockerConfig(); err != nil {
		log.WithField("Error", err).Error("Error loading docker config.")
		return func() (string, error) {
			return "", fmt.Errorf("Unable to load Docker Config. Cannot provide auth token.")
		}
	} else {
		return getPrivilegeFunc(cf, registry)
	}
}

func getPrivilegeFunc(cf configfile.ConfigFile, registry string) types.RequestPrivilegeFunc {
	privilegeFunc := func() (string, error) {
		if len(cf.AuthConfigs) == 0 {
			err := fmt.Errorf("Auth Configs are empty. No authentication will be provided.")
			log.Error(err)
			return "", err
		} else if auth, ok := cf.AuthConfigs[registry]; !ok {
			err := fmt.Errorf("No auth info found for registry: %s", registry)
			log.Error(err)
			return "", err
		} else if resp, err := wiring.GetDockerClient().RegistryLogin(context.Background(), auth); err != nil {
			err := fmt.Errorf("Error occurred when authenticating to registry %s: ", registry, err)
			log.Error(err)
			return "", err
		} else {
			authConfig := types.AuthConfig{}
			log.WithField("Status", resp.Status).Info("Authentication completed against the registry.")
			if resp.IdentityToken != "" {
				authConfig.IdentityToken = resp.IdentityToken
			} else {
				log.Warning("This registry does not support identity tokens, and did not send one back.")

				authConfig.Username = auth.Username
				authConfig.Password = auth.Password

				if authConfig.Username == "" && authConfig.Password == "" && auth.Auth != "" {
					log.Debug("Credentials were not in username and password, but in the auth field. Unpacking")
					if up, err := base64.URLEncoding.DecodeString(auth.Auth); err != nil {
						log.Errorf("Error occurred when decoding Auth field from Base64: %v", err)
					} else if colon := strings.Index(string(up), ":"); colon >= 0 {
						strup := string(up)
						authConfig.Username = strup[0:colon]
						authConfig.Password = strup[colon+1:]
					}
				}
				authConfig.Email = auth.Email
				authConfig.ServerAddress = registry
			}

			if bytes, err := json.Marshal(authConfig); err != nil {
				err := fmt.Errorf("Unable to serialize Authconfing")
				log.Error(err)
				return "", err
			} else {
				log.Infof("AuthConfig serialized successfully")
				return base64.URLEncoding.EncodeToString(bytes), nil
			}
		}
	}

	return types.RequestPrivilegeFunc(privilegeFunc)
}

func getDockerConfig() (configfile.ConfigFile, error) {
	configJson := getConfigJson()
	if configJson == "" {
		log.Info("ConfigJson found to be empty. Not providing a privilege function. The function cannot do anything useful.")
		return configfile.ConfigFile{}, fmt.Errorf("ConfigJson empty. Can't load config file.")
	}

	cf := configfile.ConfigFile{}

	if err := json.Unmarshal([]byte(configJson), &cf); err != nil {
		return cf, fmt.Errorf("An error occurred when unmarshalling config json: %v", err)
	}

	return cf, nil
}

func getConfigJson() string {
	configJson := wiring.DockerConfigJson.StringValueWithFallback()
	if configJson == "" {
		log.Info("Loading ConfigJson from the environment if possible.")
		configJson = getConfigJsonFromEnv()
	}
	return configJson
}

func getConfigJsonFromEnv() string {
	configDir, ok := os.LookupEnv("DOCKER_CONFIG")
	if !ok || configDir == "" {
		log.Warning("DOCKER_CONFIG path not set. Attempting to look up HOME/.docker")
		configDir, _ = os.LookupEnv("HOME")
		if configDir == "" {
			log.Warning("Neither DOCKER_CONFIG nor HOME directory set. Not attempting to load config.json for registry auth.")
		} else {
			configDir = configDir + "/.docker"
		}
	}

	if configDir != "" {
		if strings.LastIndex(configDir, "/") != len(configDir)-1 {
			configDir = configDir + "/"
		}
		configFile := configDir + "config.json"

		//read the file into memory
		contents, err := ioutil.ReadFile(configFile)
		if err != nil {
			log.WithField("configjson", configFile).Error("Unable to read config.json. May not be able to authenticate to registry.")
		} else {
			log.Info("Loaded Config Json from file")
			return string(contents)
		}
	}
	return ""
}
