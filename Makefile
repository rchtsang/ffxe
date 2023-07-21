
CLEANUP?=false # cleanup flag for ssh
OPEN=          # command for opening application
ifeq ($(uname), "Darwin")
	OPEN?=open -a
else ifeq ($(uname), "Linux")
	OPEN?=xdg-open
endif



all: build

build: start-docker          ## build docker image
	docker build -t ffxe/workspace:dev docker

.PHONY: start-docker
start-docker:                ## start docker if not running
	@if ( ! docker version > /dev/null 2>&1 ); then		\
		while ( ! docker version > /dev/null 2>&1 ); do \
			sleep 1;									\
		done;											\
	fi
	@echo "Docker running!"

# .PHONY: socat
# socat:                       ## start socat (for ghidra gui)

.PHONY: ssh
ssh:                         ## ssh into docker image
	@docker run \
		--init \
		-it \
		--name=workspace \
		--rm=$(CLEANUP) \
		--entrypoint=bash \
		-e DISPLAY=$(ipconfig getifaddr en0):0 \
		-v `pwd`:/home/ffxe \
		ffxe/workspace:dev

.PHONY: stop
stop:                        ## kill running container
	@docker rm -f workspace

clean: stop                  ## kill running container and clean the image
	docker rmi ffxe/workspace:dev || true

# http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
