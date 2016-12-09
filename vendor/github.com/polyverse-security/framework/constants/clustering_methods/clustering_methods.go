package clustering_methods

const (
	ClusteringMethodEtcdDiscoveryUrl    = "etcd-discovery-url"
	ClusteringMethodAwsAutoscalingGroup = "aws-autoscaling-group"
	ClusteringMethodSingleMachine       = "single-machine"
)

var ClusteringMethods []string = []string{ClusteringMethodAwsAutoscalingGroup, ClusteringMethodEtcdDiscoveryUrl, ClusteringMethodSingleMachine}
