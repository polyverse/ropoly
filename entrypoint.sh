#!/bin/bash

LOGGER_IP=localhost

if [[ "$DIND_COMMIT" != "" ]]; then
	echo "Docker-in-Docker mode..."

	ip link add dummy0 type dummy >/dev/null
	if [[ $? -eq 0 ]]; then
    		# clean the dummy0 link
    		ip link delete dummy0 >/dev/null
	else
		echo "============== WARNING =============="
		echo "This container may not have been started in privileged mode."
		echo "The detect is a heuristic and could be wrong. However, you should try running"
		echo "it again with --privileged flag, in case something fails."
		echo "====================================="
	fi

	echo "Launching Docker Daemon....."
	dockerd --storage-driver=vfs --host=unix:///var/run/docker.sock >&/dev/null &
	while [[ "$(docker info 2>/dev/null)" == "" ]]; do
		sleep 5
		echo "Waiting for daemon to be up...."
	done
	echo "Docker daemon is running...."

	if [[ "$(getent hosts polyverse_elk | awk '{print $1}')" != "" ]]; then
		LOGGER_IP=$(getent hosts polyverse_elk | awk '{print $1}')
		sed -i -E 's|localhost:12201|'$LOGGER_IP':12201|' config.yml
		echo "Detected polyverse_elk as $LOGGER_IP."
	fi

if [[ "$1" != "" ]]; then
	echo "You have asked to run a self-healing cycling of the Docker Image: $1"
	export image_name="$1"
	
	echo "Ensuring the image you provided works."
	echo "Downlaoding the image..."
	docker pull "$image_name"

	image_info=$(docker inspect "$image_name" 2>/dev/null)
	if [[ "$image_info" == "[]" || "$image_info" == "" ]]; then
		echo "The image you provided $image_name, could not be pulled or inspected."
		echo "Exiting..."
		exit 1
	fi

	echo "Checking your image for exposed ports. We're looking for EXACTLY one."
	port_count=$(docker inspect "$image_name" | jq -r -M ".[0].ContainerConfig.ExposedPorts | length")
	if [[ "$port_count" != "1" ]]; then
		echo "Your image $image_name exposes $port_count number of ports. We want exactly ONE port exposed."
		echo "These are the ports exposed by your container:"
		docker inspect "$image_name" | jq -r -M ".[0].ContainerConfig.ExposedPorts"
		echo "Please change your image, or try a different container..."
		echo "Exiting...."
		exit 1
	fi
fi

echo "Loading the polyverse images into the daemon (this takes a while) ..."
docker load -i /images.tar.gz

#echo "Launching Portainer at: http://localhost:9000. You should be able to view the status of docker and running containers there..."
#docker run -d --name portainer -p 9000:9000 -v /var/run/docker.sock:/var/run/docker.sock portainer/portainer:1.11.0

else
  echo "Downloading images..."
  str="$(cat vfi.json | jq -r .[].address)"
  images=( $str )
  for image in "${images[@]}"
  do
    echo "--> $image"
    docker pull $image > /dev/null
  done
fi

#docker run -d -p 5601:5601 -p 8000:8000 -p 12201:12201/udp --privileged --name=polyverse_elk $(cat images.json | jq -r .polyverse_elk.address)

#docker run -d --name="demokiosk" -p 3000:3000 polyverse-add-ons.jfrog.io/demokiosk:c0a828e0e2a2f83a9276c78dc187c4b472a54019

echo "Launching Polyverse..."
docker network create polyverse_nw 2>&1 > /dev/null
docker network create polyverse_container_nw 2>&1 > /dev/null

supervisor_image=$(cat ./vfi.json | jq -r -M ".supervisor.address")
docker run -d --name polyverse_supervisor_1 -v $PWD/vfi.json:/vfi.json -e DOCKER_API_VERSION=1.24 -v /var/run/docker.sock:/var/run/docker.sock -v $PWD/config.yml:/config.yml -v $PWD/appdef.js:/appdef.js --log-driver=gelf --log-opt="gelf-address=udp://$LOGGER_IP:12201" $(cat ./vfi.json | jq -r -M ".supervisor.address") -config-yaml-file /config.yml -force-pull=false

printf "Waiting for Polyverse to start up..."
while [[ "$(docker inspect polyverse_container_manager_1 2>/dev/null)" == "[]" ]]; do
	sleep 5
	printf "."
done
printf "\n"

echo "------------------------------------------------------------------------------------------------"
echo "                                   Polyverse is now running."
echo " "
echo "------------------------------------------------------------------------------------------------"

read -n 1 -p "Press ENTER to exit..."
