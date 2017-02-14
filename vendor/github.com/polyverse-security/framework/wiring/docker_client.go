package wiring

import (
	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/swarm"
	volumetypes "github.com/docker/docker/api/types/volume"
	docker "github.com/docker/docker/client"
	fcontext "github.com/polyverse-security/framework/context"
	"golang.org/x/net/context"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

// https://nathanleclaire.com/blog/2015/10/10/interfaces-and-composition-for-effective-unit-testing-in-golang/

type (
	DockerSystemAPI interface {
		Info(ctx context.Context) (types.Info, error)
		RegistryLogin(ctx context.Context, auth types.AuthConfig) (registry.AuthenticateOKBody, error)
	}
	DockerImageAPI interface {
		ImageInspectWithRaw(ctx context.Context, image string) (types.ImageInspect, []byte, error)
		ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error)
	}
	DockerContainerAPI interface {
		ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)
		ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, containerName string) (container.ContainerCreateCreatedBody, error)
		ContainerStart(ctx context.Context, container string, options types.ContainerStartOptions) error
		ContainerStop(ctx context.Context, container string, timeout *time.Duration) error
		ContainerKill(ctx context.Context, container, signal string) error
		ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error
		ContainerDiff(ctx context.Context, container string) ([]types.ContainerChange, error)
		ContainerInspect(ctx context.Context, container string) (types.ContainerJSON, error)
	}
	DockerVolumeAPI interface {
		VolumeInspect(ctx context.Context, volumeID string) (types.Volume, error)
		VolumeCreate(ctx context.Context, options volumetypes.VolumesCreateBody) (types.Volume, error)
	}
	DockerNetworkAPI interface {
		NetworkList(ctx context.Context, options types.NetworkListOptions) ([]types.NetworkResource, error)
		NetworkCreate(ctx context.Context, name string, options types.NetworkCreate) (types.NetworkCreateResponse, error)
		NetworkConnect(ctx context.Context, networkID, container string, config *network.EndpointSettings) error
	}
	SwarmServiceAPI interface {
		ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (types.ServiceCreateResponse, error)
		ServiceInspectWithRaw(ctx context.Context, serviceID string) (swarm.Service, []byte, error)
		ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error)
		ServiceRemove(ctx context.Context, serviceID string) error
		ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (types.ServiceUpdateResponse, error)
		TaskInspectWithRaw(ctx context.Context, taskID string) (swarm.Task, []byte, error)
		TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error)
	}
	EventsAPI interface {
		Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error)
	}
	SecretsAPI interface {
		SecretInspectWithRaw(ctx context.Context, id string) (swarm.Secret, []byte, error)
	}
	DockerClient interface // http://play.golang.org/p/5zkJ1jTsJu
	{
		DockerSystemAPI
		DockerImageAPI
		DockerContainerAPI
		DockerVolumeAPI
		DockerNetworkAPI
		SwarmServiceAPI
		EventsAPI
		SecretsAPI
	}
	dockerFactory func() DockerClient
)

var (
	GetDockerClient   dockerFactory
	ResetDockerClient func()
	dockerClient      DockerClient
)

func init() {
	GetDockerClient = newDockerClient
	ResetDockerClient = func() {
		dockerClient = nil
	}
}

func newDockerClient() DockerClient {
	var err error
	//exportEnvironment
	exportEnvironment()

	dockerClient, err = docker.NewEnvClient()
	if err != nil {
		log.WithFields(log.Fields{"Error": err}).Fatal("Unable to construct docker client from the environment.")
	}

	if _, err := dockerClient.Info(fcontext.DefaultDockerTimeout()); err != nil {
		log.WithFields(log.Fields{"Error": err}).Fatal("Unable to get Docker Info (which indicates the connection to docker is not functioning correctly.)")
	}

	return dockerClient
}

func exportEnvironment() {
	log.Info("Exporting any etcd-configured Docker-endpoint values, into the environment.")
	export(DockerHostname, "DOCKER_HOST")
	export(DockerTlsVerify, "DOCKER_TLS_VERIFY")
	export(DockerApiVersion, "DOCKER_API_VERSION")
	export(DockerCertPath, "DOCKER_CERT_PATH")

	exportCertFile(DockerCA, "ca.pem")
	exportCertFile(DockerCert, "cert.pem")
	exportCertFile(DockerKey, "key.pem")
}

func export(key *ConfigKey, envName string) {
	if value, ok := os.LookupEnv(envName); ok {
		log.WithField(envName, value).Info("This environment variable already set. Not overriding it.")
		return
	} else if value := key.StringValueWithFallback(); value != "" {
		log.WithField(envName, value).Info("Setting Environment Variable")
		os.Setenv(envName, value)
	}
}

func exportCertFile(key *ConfigKey, fileName string) {
	if contents := key.StringValueWithFallback(); len(contents) > 0 { //only do this if the contents are non-empty.
		if certPath, ok := os.LookupEnv("DOCKER_CERT_PATH"); !ok {
			log.Error("DOCKER_CERT_PATH not exported. Don't know where to save this file.")
		} else {
			if strings.LastIndex(certPath, "/") != len(certPath)-1 {
				certPath = certPath + "/"
			}

			certFile := certPath + fileName
			ioutil.WriteFile(certFile, []byte(contents), 0)
		}
	}

}
