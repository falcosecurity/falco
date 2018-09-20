build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s" -o falco-sns main.go

deps:
	go get -u github.com/aws/aws-sdk-go/

clean:
	rm falco-sns

docker: build
	docker build -t sysdig/falco-sns .
	docker push sysdig/falco-sns
