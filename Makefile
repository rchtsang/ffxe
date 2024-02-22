
SHELL:=/bin/bash
WORKDIR?=/home/ffxe		# working directory in docker container
CLEANUP?=false 			# cleanup flag for ssh
OPEN=          			# command for opening application
ifeq ($(uname), "Darwin")
	OPEN?=open -a
	DISPLAY=$(ipconfig getifaddr en0):0
else ifeq ($(uname), "Linux")
	OPEN?=xdg-open
	DISPLAY=$$(DISPLAY)
endif



all: build

.PHONY: install
install:                     ## install ffxe in current pip environment
	@pip install -e .

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

.PHONY: container
container: start-docker        ## start container if not yet running
	@if [ ! $$(docker ps -q -f name=/ffxe-workspace) ]; then \
		docker run 									\
			-t -d									\
			--privileged							\
			--init 									\
			--name=ffxe-workspace 					\
			--rm=$(CLEANUP) 						\
			--entrypoint=bash 						\
			-v `pwd`:$(WORKDIR) 					\
			ffxe/workspace:dev;						\
	fi

# add this for x11 forwarding on linux
# -e DISPLAY=$(DISPLAY)				 	\

.PHONY: ssh
ssh: container               ## ssh into docker image
	@docker exec -w $(WORKDIR) -it ffxe-workspace /bin/bash

.PHONY: stop
stop:                        ## kill running container
	@docker rm -f ffxe-workspace

clean: stop                  ## kill running container and clean the image
	docker rmi ffxe/workspace:dev || true

# http://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
help:
	@echo "Makefile Usage: make [target]"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
