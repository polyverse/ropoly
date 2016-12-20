package handlers

import (
	"golang.org/x/net/context"
	"fmt"
        "io"
        "net/http"
        "encoding/json"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	log "github.com/Sirupsen/logrus"
)

func DockerHandler(w http.ResponseWriter, r *http.Request) {
	log.Infof("r.URL.Path = %s", r.URL.Path);

	client, err := client.NewEnvClient()
	if err != nil {
		log.Panic(err)
	}

	containers, err := client.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		log.Panic(err)
	}

	b, err := json.Marshal(containers)
        if err != nil {
                log.WithFields(log.Fields{"err":err}).Errorf("Encountered error marshaling to JSON.")
                io.WriteString(w, fmt.Sprintf("Error: %s\n", err))
        } else {
                log.Infof("%s", string(b))
                io.WriteString(w, fmt.Sprintf("%s\n", string(b)))
        }
}
