package introspect

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/polyverse-security/framework/wiring"
	"golang.org/x/net/context"
	"io/ioutil"
	"os"
	"strings"
)

func ThisContainer() (types.ContainerJSON, error) {
	dc := wiring.GetDockerClient()
	containerId, err := ThisContainerId()
	if err != nil {
		log.WithField("Error", err).Error("Error when obtaining container ID for the currently running container.")
		return types.ContainerJSON{}, err
	}

	return dc.ContainerInspect(context.Background(), containerId)
}

func ThisContainerId() (string, error) {
	log.Debug("About to retrieve ID for this container. Looking for /proc/self/cgroup file first (https://github.com/docker/docker/issues/8427).")
	if filebuf, err := ioutil.ReadFile("/proc/self/cgroup"); err != nil {
		if os.IsNotExist(err) {
			log.WithField("Error", err).Info("The file /proc/self/cgroup does not exist. The docker/linux kernel version doesn't support it, or we're not running on linux to begin with. This is not a problem.")
		} else {
			log.WithField("Error", err).Error("Error when reading the file /proc/self/cgroup, but the error was not due to a non-existing file (which would be fine.) Please look into why there's an error when reading it.")
		}
	} else {
		log.Info("Successfully read /proc/self/cgroup to attempt to find out the ID of the currently running container...")
		if containerId, err := getContainerIdFromCgroupContents(string(filebuf)); err == nil {
			return containerId, nil
		}
	}
	log.Debug("No docker container ID found in the file /proc/self/cgroup. Proceeding to determine container ID using a more traditional method of getting the OS Hostname.")
	return os.Hostname()
}

/*
Separted this out so we can unit-test it.
*/
func getContainerIdFromCgroupContents(contents string) (string, error) {
	lines := strings.Split(contents, "\n")
	for _, line := range lines {
		if strings.Contains(line, "/docker/") {
			log.Debugf("Found a line in /proc/self/cgroup which might contain the docker container id: %s", line)
			docker_prefix_idx := strings.Index(line, "/docker/")
			if docker_prefix_idx == -1 {
				log.Errorf("Something went terribly wrong. The string \"/docker/\" is contained in the line we're parsing, but it's index is -1 (indicating it does not exist.) Look at this line and determine what's wrong: %s", line)
			} else {
				containerId := line[docker_prefix_idx+len("/docker/"):]
				log.WithField("ContainerId", containerId).Info("Successfully obtained docker container ID from /proc/self/cgroup.")
				return strings.TrimSpace(containerId), nil
			}
		}
	}
	return "", fmt.Errorf("Didn't find any docker container prefixes in the cgroups file, apparently. This is upto the caller to figure out.")
}
