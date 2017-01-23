package introspect

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/swarm"
	"github.com/polyverse-security/framework/context"
	"github.com/polyverse-security/framework/wiring"
)

//These are swarm labels
//          "Labels": {
//	"com.docker.swarm.node.id": "y203da3n97wn4zhx543ytcyaj",
//	"com.docker.swarm.service.id": "yhmkvwky6tcpz91ni8jcjqyls",
//	"com.docker.swarm.service.name": "jovial_lewin",
//	"com.docker.swarm.task": "",
//	"com.docker.swarm.task.id": "p8i05ry11mxuggygvnrn6u0z9",
//	"com.docker.swarm.task.name": "jovial_lewin.1.p8i05ry11mxuggygvnrn6u0z9"
//}

func ThisService() (swarm.Service, error) {
	dc := wiring.GetDockerClient()
	if serviceId, err := ThisServiceId(); err != nil {
		log.WithField("Error", err).Error("Unable to get Service ID for the current container.")
		return swarm.Service{}, err
	} else {
		service, _, err := dc.ServiceInspectWithRaw(context.DefaultDockerTimeout(), serviceId)
		return service, err
	}
}

/**
Returns the name of this task under a service.
*/
func ThisTaskId() (string, error) {
	return getLabelFromContainer("com.docker.swarm.task.id")
}

func ThisServiceId() (string, error) {
	return getLabelFromContainer("com.docker.swarm.service.id")
}

func ThisServiceTaskList() ([]swarm.Task, error) {
	serviceId, err := ThisServiceId()
	if err != nil {
		log.WithField("Error", err).Error("Unable to get service Id for this container. Cannot get tasks under the service, without a service Id.")
	}

	dc := wiring.GetDockerClient()
	serviceIdFilter := filters.NewArgs()
	serviceIdFilter.Add("service", serviceId)

	return dc.TaskList(context.DefaultDockerTimeout(), types.TaskListOptions{
		Filters: serviceIdFilter,
	})
}

func getLabelFromContainer(label string) (string, error) {
	if container, err := ThisContainer(); err != nil {
		log.WithField("Error", err).Error("Unable to find the container info for the current container. We cannot look up the labels for it.")
		return "", err
	} else {
		log.Debugf("Attempting to look up this label in the container: %s", label)
		if value, ok := container.Config.Labels[label]; ok {
			log.WithFields(log.Fields{"ContainerId": container.ID, "LabelValue": value, "LabelName": label}).Info("Found value container label. This was easy.")
			return value, nil
		} else {
			return "", fmt.Errorf("This container does not seem to be a part of a Swarm Service. Unable to fetch the expected swarm label (%s) on the container. Labels found on this container: %++v", label, container.Config.Labels)
		}
	}
}
