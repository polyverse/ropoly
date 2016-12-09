package labels

const (
	POLYVERSE_ASSET_LABEL_KEY   = "io.polyverse" //The key used on container labels
	POLYVERSE_ASSET_LABEL_VALUE = ""

	POLYVERSE_CONTAINER_LABEL_KEY             = "io.polyverse.container_type" //The key used on container labels
	POLYVERSE_CONTAINER_LABEL_VALUE_CUSTOMER  = "customer_container"
	POLYVERSE_CONTAINER_LABEL_VALUE_POLYVERSE = "polyverse_container"

	APP_CONTAINER_BINDING_PORT_KEY = "io.polyverse.container.binding_port" //The port to bind to as provided by route info

	APP_CONTAINER_CHAIN_INFO_LABEL_KEY = "io.polyverse.chain.info"

	APP_CONTAINER_CHAIN_FIRST_LABEL_KEY   = "io.polyverse.chain.first"
	APP_CONTAINER_CHAIN_FIRST_LABEL_VALUE = "FirstContainerInChain"
)
