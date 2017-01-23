package registry_auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/cliconfig/configfile"
	"github.com/polyverse-security/framework/context"
	"github.com/polyverse-security/framework/wiring"
	"io/ioutil"
	"os"
	"strings"
)

const defaultRegistry = "https://index.docker.io/v1/"

var (
	noRegistryFoundError error = fmt.Errorf("No registry of this name found in config json.")
)

func noOpPrivilegeFunc() (string, error) {
	log.Info("No op registry auth function called. Returning an empty auth token, and no error.")
	return "", nil
}

func GetPrivilegeFunc() types.RequestPrivilegeFunc {
	if function, err := GetPrivilegeFuncForRegistry(defaultRegistry); err == nil {
		return function
	} else {
		if err == noRegistryFoundError {
			log.Error("No auth credentials found for default registry (docker.io) in config json.")
		} else {
			log.WithField("Error", err).Error("An unexpected error occurred when retrieving a privilege function for the default registry (docker.io).")
		}
		return noOpPrivilegeFunc
	}
}

func GetPrivilegeFuncForImage(image string) types.RequestPrivilegeFunc {
	log.Infof("Getting privilege function for image: %s", image)

	//split the image into parts if possible
	fragments := strings.Split(image, "/")
	log.WithFields(log.Fields{"ImageName": image, "Fragments": fragments}).Debug("Broken down image name into fragments separated by /")
	if len(fragments) > 1 {
		registry := fragments[0]
		log.WithField("RegistryCandidateFragment", registry).Info("Since number of fragments was more than one, we're going to treat the first segment as registry...")
		if function, err := GetPrivilegeFuncForRegistry(registry); err == nil {
			log.WithField("Registry", registry).Debug("Registry of this name, had auth entry in config json. Returning auth function for it.")
			return function
		} else if err == noRegistryFoundError {
			log.WithFields(log.Fields{"Registry": registry, "Image": image}).Warning("If this image's prefix was indeed meant to be a registry specifier, then we didn't find auth details for it. This function will try and return auth credentials for the default docker.io registry, if one is available.")
		} else {
			log.WithFields(log.Fields{"Registry": registry, "Image": image, "Error": err}).Error("An unexpected error occurred when trying to retrieve registry auth credentials for this image/registry. The error was not expected. We're going to proceed to fallbacks to docker.io and see if something else will work.")
		}
	}

	log.WithField("Registry", defaultRegistry).Warning("No specific registry found. Obtaining auth function for the default docker.io registry.")
	if function, err := GetPrivilegeFuncForRegistry(defaultRegistry); err == nil {
		log.WithField("Registry", defaultRegistry).Debug("Registry of this name, had auth entry in config json. Returning auth function for it.")
		return function
	} else {
		if err == noRegistryFoundError {
			log.WithFields(log.Fields{"Registry": defaultRegistry}).Warning("There were no credentials found for the default docker.io registry in config json. Going to return a no-op privilege function.")
		} else {
			log.WithFields(log.Fields{"Registry": defaultRegistry}).Error("An unexpected error occurred when trying to obtain a privilege function. Going to return a no-op privilege function.")
		}
		return noOpPrivilegeFunc
	}
}

func GetPrivilegeFuncForRegistry(registry string) (types.RequestPrivilegeFunc, error) {

	if registry == "docker.io" { //Special case
		log.Info("Registry docker.io being resolved as a special case to the default registry URL")
		registry = defaultRegistry
	}

	log.Infof("Getting privilege function for registry: %s", registry)
	if cf, err := getDockerConfig(); err != nil {
		log.WithField("Error", err).Error("Error loading docker config.")
		return nil, fmt.Errorf("Unable to load Docker Config. Cannot provide the privilege function to generate credentials.")
	} else {
		return getPrivilegeFunc(cf, registry)
	}
}

func getPrivilegeFunc(cf configfile.ConfigFile, registry string) (types.RequestPrivilegeFunc, error) {

	if len(cf.AuthConfigs) == 0 {
		err := fmt.Errorf("Auth Configs are empty. No authentication will be provided.")
		log.Error(err)
		return nil, noRegistryFoundError
	} else if _, ok := cf.AuthConfigs[registry]; !ok {
		err := fmt.Errorf("No auth info found for registry: %s", registry)
		log.Error(err)
		return nil, noRegistryFoundError
	}

	privilegeFunc := func() (string, error) {
		auth := cf.AuthConfigs[registry]

		if resp, err := wiring.GetDockerClient().RegistryLogin(context.DefaultDockerTimeout(), auth); err != nil {
			err := fmt.Errorf("Error occurred when authenticating to registry %s: ", registry, err)
			log.Error(err)
			return "", err
		} else {
			authConfig := types.AuthConfig{}
			log.WithField("Status", resp.Status).Infof("Authentication completed against the registry: %s", registry)
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

	return types.RequestPrivilegeFunc(privilegeFunc), nil
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
