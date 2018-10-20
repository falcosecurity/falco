#!/bin/sh

echo "Pulling alpine:latest image to docker-in-docker instance"
curl -X POST 'http://localhost:2375/images/create?fromImage=alpine&tag=latest'

echo "Creating container mounting /etc from host-machine"
curl -H 'Content-Type: application/json' -d @docker123321-mysql-container.json -X POST 'http://localhost:2375/containers/create?&name=docker123321-mysql'

echo "Running container mounting /etc from host-machine"
curl -H 'Content-Type: application/json' -X POST 'http://localhost:2375/containers/docker123321-mysql/start'




