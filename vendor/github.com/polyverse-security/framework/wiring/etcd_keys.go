package wiring

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/polyverse-security/framework/context"
	"time"
)

var (
	bootstrapInProgress      bool
	overrides                map[string]string
	etcdKeyReadTimeout       time.Duration = time.Duration(20) * time.Second //This is a high value due to that weird Mac bug of delaying connections by 10 seconds.
	bootstrapInProgressError error         = fmt.Errorf("StringValue skipping Etcd query, because Bootstrap is in progress")
)

func SetBootstrapInProgress(bip bool) {
	bootstrapInProgress = bip
	log.WithField("bootstrapInProgress", bootstrapInProgress).Info("SetBootstrapInProgress.")
}

func SetEtcdKeyOverrides(o map[string]string) {
	if overrides != nil {
		log.Warning("Etcd Override map has already been set. You may not set it twice. It is a serious bug.")
	}
	overrides = o
}

func SetEtcdKeyReadTimeout(timeout time.Duration) {
	etcdKeyReadTimeout = timeout
}

type EtcdKey struct {
	keyName      string
	defaultValue string
	description  string
	subKeys      []*EtcdKey
}

/*
This package provides global configuration from one of N etcd servers that may be running.
*/

func newEtcdKey(keyName string, defaultValue string, description string) *EtcdKey {
	return &EtcdKey{
		keyName:      keyName,
		defaultValue: defaultValue,
		subKeys:      []*EtcdKey{},
		description:  description,
	}
}

func (e *EtcdKey) Name() string {
	return e.keyName
}

func (e *EtcdKey) StringValue() (string, error) {
	if bootstrapInProgress {
		return "", bootstrapInProgressError
	}

	etcdClient := NewEtcdClientCoreOS()
	log.WithFields(log.Fields{"Key": e.Name()}).Debug("Attempting to fetch global configuraton key from etcd.")
	ctx := context.WithTimeout(etcdKeyReadTimeout)

	if resp, err := etcdClient.Get(ctx, e.Name()); err != nil {
		//Timeout in half a second
		log.WithFields(log.Fields{"Error": err, "Key": e.Name(), "Timeout": etcdKeyReadTimeout}).Error("Error occurred fetching global configuraton key from etcd.")
		return "", err
	} else if resp == nil || len(resp.Kvs) != 1 {
		return "", fmt.Errorf("Either the response was invalid, or no keys of this name were found in etcd: %s", e.Name())
	} else {
		return string(resp.Kvs[0].Value), nil
	}
}

func (e *EtcdKey) StringValueWithFallback() string {
	if value, err := e.StringValue(); err == nil {
		return value
	} else {
		if err != bootstrapInProgressError {
			log.WithField("Error", err).Error("An error occurred fetching this key from etcd. Attempting to find it in the override map.")
		} else {
			log.WithField("Error", err).Debug("An error occurred fetching this key from etcd. Attempting to find it in the override map.")
		}
		return e.StringFallbackValue()
	}
}

func (e *EtcdKey) StringFallbackValue() string {
	if value, err := e.fromOverrideMap(); err == nil {
		return value
	} else {
		log.WithField("Error", err).Debugf("Value not found in the override map. Returning default: %v", e.defaultValue)
		return e.defaultValue
	}
}

func (e *EtcdKey) DefaultValue() string {
	return e.defaultValue
}

func (e *EtcdKey) Description() string {
	return e.description
}

func (e *EtcdKey) SubKeys() []*EtcdKey {
	return e.subKeys
}

func (e *EtcdKey) fromOverrideMap() (string, error) {
	if overrides == nil {
		return "", fmt.Errorf("Override Map was not set.")
	} else if ovalue, ok := overrides[e.Name()]; !ok {
		return "", fmt.Errorf("Key %s not found in override map", e.Name())
	} else {
		return ovalue, nil
	}
}

func (e *EtcdKey) NewSubKey(keyName string, defaultValue string, description string) *EtcdKey {
	subKey := newEtcdKey(e.keyName+"/"+keyName, defaultValue, description)
	e.subKeys = append(e.subKeys, subKey)
	return subKey
}

var (
	ConfigRootKey = newEtcdKey("/polyverse/config", "", "This is the root configuration key. It is merely a prefix and not a real key whose value matters.")

	//Core Polyverse-wide settings
	ScrambledBinaries = ConfigRootKey.NewSubKey("scrambled_binaries", "true", "true/false - Determines if Polyverse uses Scrambled Binaries whenever possible.")
	VFI               = ConfigRootKey.NewSubKey("vfi", "{}", "Mandatory key - it contains the JSON representation of the VFI that should be used for launching Polyverse.")
	RotationInterval  = ConfigRootKey.NewSubKey("rotation_internval", "1", "In seconds, the interval after which Polyverse's own components are rotated. Zero indicates no rotation. Only components whose cluster size is greater than one are rotated (because polyverse requires at least one replica of all components at all times.)")

	//Router settings
	RouterRootKey            = ConfigRootKey.NewSubKey("router", "", "This key is merely a prefix for all router configurations. It's value doesn't represent or affect anything.")
	TrackExternalConnections = RouterRootKey.NewSubKey("track_external_connections", "false", "true/false - Determines whether external (connections coming into the router from the internet/outside) are tracked in etcd for visibility.")
	TrackInternalConnections = RouterRootKey.NewSubKey("track_internal_connections", "false", "true/false - Determines whether internal connections (connections from router to within systems in polyverse such as customer app containers) are tracked in etcd for visibility. This key is mandatory if you want connection-training enabled and working correctly.")
	RouterPort               = RouterRootKey.NewSubKey("port", "8080", "The port on which the router should bind itself.")
	RouterSslOn              = RouterRootKey.NewSubKey("ssl_on", "false", "true/false - Whether the router exposes an SSL (TLS) interface or a non-Secure (plain HTTP) interface.")
	RouterSealKey            = RouterRootKey.NewSubKey("seal_key", "", "A vulcand Seal Key used to seal the SSL cert and private key (so vulcan can interpret it correctly. Usually not necessary to be set manually - necessary for very advanced use cases.")
	RouterSslCert            = RouterRootKey.NewSubKey("ssl_cert", "", "The SSL Certificate to be presented to the client for authentication.")
	RouterSslPrivateKey      = RouterRootKey.NewSubKey("ssl_private_key", "", "The private key backing the SSL cert (this proving you are who you say you are.)")
	RouterSslHostname        = RouterRootKey.NewSubKey("ssl_hostname", "", "The hostname/domain name for which this SSL cert is valid. (e.g. polyverse.io)")

	//Docker settings
	DockerRootKey    = ConfigRootKey.NewSubKey("docker", "", "This is the root prefix key for all docker-connection settings (allowing Polyverse to connect to the Docker/Swarm fabric.) This key does not do anything and means nothing.")
	DockerConfigJson = DockerRootKey.NewSubKey("config_json", "", "The config.json for Docker Client connectivity. Specifically the contents of the file $DOCKER_CONFIG/config.json (https://docs.docker.com/engine/reference/commandline/cli/#/environment-variables)")
	DockerHostname   = DockerRootKey.NewSubKey("hostname", "", "The hostname:port to which Polyverse should connect to for the Docker Remote API. Specifically the value you would place in DOCKER_HOST environment variable for the CLI (https://docs.docker.com/engine/reference/commandline/cli/#/environment-variables)")
	DockerCertPath   = DockerRootKey.NewSubKey("cert_path", "", "Docker certificate path that contains cert.pem, ca.pem and key.pem files. Either the path is mounted into the container, or it is where the files are stored from the keys, when provided. These autheticate polyverse to your docker endpoint")
	DockerCA         = DockerRootKey.NewSubKey("ca_pem", "", "The CA Cert to authenticate the client cert with (if not already presented in the cert_path).")
	DockerCert       = DockerRootKey.NewSubKey("cert_pem", "", "The Client Certificate that authenticates the client to the docker endpoint.")
	DockerKey        = DockerRootKey.NewSubKey("key_pem", "", "The client certificate private key allowing the certificate to be authenticated to the docker endpoint.")
	DockerTlsVerify  = DockerRootKey.NewSubKey("tls_verify", "", "Specifies whether the client should use TLS to communicate with the Docker Remote API, and whether to verify the endpoint. Same as DOCKER_TLS_VERIFY variable for the docker CLI (https://docs.docker.com/engine/reference/commandline/cli/#/environment-variables)")
	DockerApiVersion = DockerRootKey.NewSubKey("api_version", "", "The Docker Remote API version to use when calling the endpoint. Same as DOCKER_API_VERSION environment variable value for the cli (https://docs.docker.com/engine/reference/commandline/cli/#/environment-variables)")

	MonitoringRootKey      = ConfigRootKey.NewSubKey("monitoring", "", "This key is the root prefix for all monitoring/logging related configurations. In and of itself, this key has no value or purpose.")
	DebugLevel             = MonitoringRootKey.NewSubKey("log_level", "info", "This key controls the log level for Polyverse (and only polyverse components.) Valid values: debug, info, warning, error, panic") //Sets Log level (may change it some time in the future.) - values “debug”, “info”, “warning”, “error"
	LogTypeKey             = MonitoringRootKey.NewSubKey("docker_log_driver", "json-file", "This key specifies the log driver to be used for container-level logging (for Docker.) See possible values here: https://docs.docker.com/engine/admin/logging/overview/")
	LoggerOpts             = MonitoringRootKey.NewSubKey("docker_log_opts", "{}", "This key specifies options to be passed to the docker log driver, specified in docker_log_driver key. The value of this key is a JSON structure which is the map of option:value of the form: {option1: \"value1\", option2: \"value2\"}. You may, under certain cases, provide a JSON array of strings of the form: [\"option1=value1\", \"option2=value2\"] See available options for each driver here: https://docs.docker.com/engine/admin/logging/overview/")
	StatsdEndpoint         = MonitoringRootKey.NewSubKey("statsd_endpoint", "127.0.0.1:8125", "This key specifies the endpoint to send statsd UDP metrics to. It must be a hostname that includes the UDP listener port. For example: statterhost:8125")
	LogContainerChangesKey = MonitoringRootKey.NewSubKey("log_container_changes", "false", "true/false - Specifies if the changes made in a container during its lifetime should be emitted to logs, before a container is killed. This is a potentially expensive operation, and you should measure the performance impact before enabling it.")
	LogSourceLine          = MonitoringRootKey.NewSubKey("log_source_line", "false", "true/false - Specifies if each log entry should include the line and filename within the source code where the log entry call was made from.")                                                                                                                                                                  //"true"/"false" - Whether the line of source code is added to each log entry.
	LogCallstack           = MonitoringRootKey.NewSubKey("log_callstack", "false", "true/false - Specifies if each log entry should include the full callstack of the log function call.")                                                                                                                                                                                                            //"true"/"false" - Whether the full callstack is logged for each log entry (Very expensive operation.)
	LogMetrics             = MonitoringRootKey.NewSubKey("log_metrics", "false", "true/false - Specifies if metrics (counters, timers, gauges, etc.) which are emitted over the statsd protocol, should also be emitted as log entries (in some situations, your log processing pipeline is also capable of processing metrics).")                                                                    //"true"/"false" - Whether all metrics are also duplicated as log entries.
	StatsToConsole         = MonitoringRootKey.NewSubKey("stats_to_console", "false", "true/false - Specifies if metrics (counters, timers, gauges, etc.) should also be written to console (this is a very specific debugging use-case and has little real-world applicability.)")                                                                                                                   //"true"/"false" - Whether all metrics are also emitted to the console.
	StatterClusterPrefix   = MonitoringRootKey.NewSubKey("statter_cluster_name", "unnamed_cluster", "Specifies a name for this polyverse cluster that should be prefixed to all metrics that are emitted. This allows you to collect metrics from multiple polyverses and differentiate them in your metrics platform.")                                                                              //The unique cluster name for this running cluster - default "unnamed_cluster".
	Profiler               = MonitoringRootKey.NewSubKey("profiler", "off", "on/off/heap - This enables the golang profiler or makes it dump the entire heap. The trigger is a key-change. So if you want a heap dump, set the key to off first, and then set it to heap to get one dump. This is an expensive, intrusive, and very advanced operation. You should not need to use this frequently.") //"on", "off", "heap" - on: Start CPU Profiling, off: Stop CPU Profiling, heap: Profile the heap
	ProfilerOutputFilename = MonitoringRootKey.NewSubKey("profiler_output_filename", "/polyverse-service.prof", "Specifies where the profiler output (when the profiler key is used) should be stored. The file will be within the container for each profiled service, unless this location is pointed to a volume mounted externally.")                                                             //Where the profiler output should be saved
	ProfilerHeapOutputFile = MonitoringRootKey.NewSubKey("profiler_heap_output_filename", "/polyverse-service-heap.prof", "Specifies where the profiler heap output (when the profiler key is used) should be stored. The file will be within the container for each profiled service, unless this location is pointed to a volume mounted externally.")                                              //Where the heap should be saved

	//Managed settings (containers we manage)
	ManagedContainersRootKey = ConfigRootKey.NewSubKey("managed_containers", "", "This is the root prefix key for settings relating to containers that we manage for the applications Polyverse hosts. In and of itself, this key has no meaning.")
	ManagedContainersNetwork = ManagedContainersRootKey.NewSubKey("network", "managed_container_nw", "This key provides the name of the docker network to use for joining managed containers to. You should not have to change this setting from its default in most cases.")

	//Various component-level settings
	ComponentsRootKey = ConfigRootKey.NewSubKey("components", "", "This is the root prefix key for runtime, management and supervision settings related to specific polyverse components.")

	//Etcd Component
	ComponentEtcd            = ComponentsRootKey.NewSubKey("etcd", "", "This is the root prefix key for the etcd component's runtime, management and supervision settings.")
	ComponentEtcdClusterSize = ComponentEtcd.NewSubKey("cluster_size", "1", "This key specifies how may instances (nodes/replicas) of etcd should be running in the swarm for redundancy.")

	ComponentNsq            = ComponentsRootKey.NewSubKey("nsq", "", "This is the root prefix key for the NSQ component's runtime, management and supervision settings.")
	ComponentNsqClusterSize = ComponentNsq.NewSubKey("cluster_size", "1", "This key specifies how may instances of NSQ should be running in the swarm for redundancy.")

	ComponentRouter            = ComponentsRootKey.NewSubKey("router", "", "This is the root prefix key for the Router component's runtime, management and supervision settings.")
	ComponentRouterClustersize = ComponentRouter.NewSubKey("cluster_size", "1", "This key specifies how may instances of Router should be running in the swarm for redundancy.")

	ComponentContainerManager            = ComponentsRootKey.NewSubKey("container_manager", "", "This is the root prefix key for the Container Manager component's runtime, management and supervision settings.")
	ComponentContainerManagerClusterSize = ComponentContainerManager.NewSubKey("cluster_size", "1", "This key specifies how may instances of Container Manager should be running in the swarm for redundancy.")

	//Where the router stores active connections information
	ExternalConnectionsBaseKey = "/polyverse/active_connections/external/"
	InternalConnectionsBaseKey = "/polyverse/active_connections/internal/"

	AppClientRootKey = "/apps"
)
