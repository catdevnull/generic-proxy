build:
    docker build -t ghcr.io/catdevnull/generic-proxy --platform linux/amd64 .

push: build
    docker push ghcr.io/catdevnull/generic-proxy:latest
