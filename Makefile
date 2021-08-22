.PHONY: clean build

PWD=$(shell pwd)
VER?="1.0.0"

default: clean build

clean: 
	rm -rf sslproxy

build:
	docker run -it --rm \
		-v $(PWD):/app \
		--env GO111MODULE=on \
		--env CGO_ENABLED=0 \
		--env GOOS=linux \
		--env GOARCH=amd64 \
		--workdir=/app \
		golang:1.16.5-alpine3.13 \
		go build -ldflags="-s -w" -o sslproxy .
	docker build --force-rm -t xuanloc0511/sslproxy:$(VER) -f Dockerfile $(PWD)
	docker tag xuanloc0511/sslproxy:$(VER) xuanloc0511/sslproxy:latest