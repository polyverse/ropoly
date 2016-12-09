package mocks

import (
	"bytes"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/swarm"
	volumetypes "github.com/docker/docker/api/types/volume"
	"github.com/polyverse-security/framework/wiring"
	"golang.org/x/net/context"
	"io"
	"io/ioutil"
	"time"
)

type (
	DockerSystemAPIMock struct {
	}
	DockerImageAPIMock struct {
	}
	DockerContainerAPIMock struct {
		ContainersLister func() []types.Container
	}
	DockerVolumeAPIMock struct {
	}
	DockerNetworkAPIMock struct {
	}
	DockerSwarmServiceAPIMock struct {
	}
	DockerClientMock struct {
		DockerSystemAPIMock
		DockerImageAPIMock
		DockerContainerAPIMock
		DockerVolumeAPIMock
		DockerNetworkAPIMock
		DockerSwarmServiceAPIMock
	}
)

var (
	docker_mock *DockerClientMock
)

func DockerMockFactory() wiring.DockerClient {
	if docker_mock == nil {
		docker_mock = &DockerClientMock{}
	}
	return *docker_mock
}

func (dm DockerSystemAPIMock) Info(ctx context.Context) (types.Info, error) {
	return types.Info{}, nil
}

func (dm DockerSystemAPIMock) RegistryLogin(ctx context.Context, auth types.AuthConfig) (registry.AuthenticateOKBody, error) {
	return registry.AuthenticateOKBody{}, nil
}

func (dm DockerImageAPIMock) ImageInspectWithRaw(ctx context.Context, image string) (types.ImageInspect, []byte, error) {
	return types.ImageInspect{}, []byte{}, nil
}

func (dm DockerImageAPIMock) ImagePull(ctx context.Context, ref string, options types.ImagePullOptions) (io.ReadCloser, error) {
	return ioutil.NopCloser(bytes.NewReader([]byte(""))), nil
}

func (dm DockerContainerAPIMock) ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error) {
	if dm.ContainersLister == nil {
		return []types.Container{}, nil
	}
	return dm.ContainersLister(), nil
}

func (dm DockerContainerAPIMock) ContainerCreate(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, networkingConfig *network.NetworkingConfig, containerName string) (container.ContainerCreateCreatedBody, error) {
	return container.ContainerCreateCreatedBody{}, nil
}

func (dm DockerContainerAPIMock) ContainerStart(ctx context.Context, container string, options types.ContainerStartOptions) error {
	return nil
}

func (dm DockerContainerAPIMock) ContainerStop(ctx context.Context, container string, timeout *time.Duration) error {
	return nil
}

func (dm DockerContainerAPIMock) ContainerKill(ctx context.Context, container, signal string) error {
	return nil
}

func (dm DockerContainerAPIMock) ContainerRemove(ctx context.Context, container string, options types.ContainerRemoveOptions) error {
	return nil
}

func (dm DockerContainerAPIMock) ContainerDiff(ctx context.Context, container string) ([]types.ContainerChange, error) {
	return []types.ContainerChange{}, nil
}

func (dm DockerContainerAPIMock) ContainerInspect(ctx context.Context, container string) (types.ContainerJSON, error) {
	return types.ContainerJSON{}, nil
}

func (dm DockerVolumeAPIMock) VolumeInspect(ctx context.Context, volumeID string) (types.Volume, error) {
	return types.Volume{}, nil
}

func (dm DockerVolumeAPIMock) VolumeCreate(ctx context.Context, options volumetypes.VolumesCreateBody) (types.Volume, error) {
	return types.Volume{}, nil
}

func (dm DockerNetworkAPIMock) NetworkList(ctx context.Context, options types.NetworkListOptions) ([]types.NetworkResource, error) {
	return []types.NetworkResource{}, nil
}

func (dm DockerNetworkAPIMock) NetworkCreate(ctx context.Context, name string, options types.NetworkCreate) (types.NetworkCreateResponse, error) {
	return types.NetworkCreateResponse{}, nil
}

func (dm DockerNetworkAPIMock) NetworkConnect(ctx context.Context, networkID, container string, config *network.EndpointSettings) error {
	return nil
}

func (sm DockerSwarmServiceAPIMock) ServiceCreate(ctx context.Context, service swarm.ServiceSpec, options types.ServiceCreateOptions) (types.ServiceCreateResponse, error) {
	return types.ServiceCreateResponse{}, nil
}

func (sm DockerSwarmServiceAPIMock) ServiceInspectWithRaw(ctx context.Context, serviceID string) (swarm.Service, []byte, error) {
	return swarm.Service{}, []byte{}, nil
}

func (sm DockerSwarmServiceAPIMock) ServiceList(ctx context.Context, options types.ServiceListOptions) ([]swarm.Service, error) {
	return []swarm.Service{}, nil
}

func (sm DockerSwarmServiceAPIMock) ServiceRemove(ctx context.Context, serviceID string) error {
	return nil
}

func (sm DockerSwarmServiceAPIMock) ServiceUpdate(ctx context.Context, serviceID string, version swarm.Version, service swarm.ServiceSpec, options types.ServiceUpdateOptions) (types.ServiceUpdateResponse, error) {
	return types.ServiceUpdateResponse{}, nil
}

func (sm DockerSwarmServiceAPIMock) TaskInspectWithRaw(ctx context.Context, taskID string) (swarm.Task, []byte, error) {
	return swarm.Task{}, []byte{}, nil
}

func (sm DockerSwarmServiceAPIMock) TaskList(ctx context.Context, options types.TaskListOptions) ([]swarm.Task, error) {
	return []swarm.Task{}, nil
}
