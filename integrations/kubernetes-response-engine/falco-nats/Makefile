build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o falco-nats main.go

deps:
	go get -u github.com/nats-io/go-nats

clean:
	rm falco-nats

docker: build
	docker build -t sysdig/falco-nats .
	docker push sysdig/falco-nats
