FROM ubuntu:latest

# NOTE: to purge the Docker unused files use:
#   $ docker system prune -a
# NOTE: to run shell on the image:
#   $ docker run -it YOUR_IMAGE_NAME sh
#   $ sudo -u YOUR_USERNAME docker run -it YOUR_IMAGE_HASH bash
#   FOR EXAMPLE:
#     $ sudo -u `whoami` docker run -it c8c279906c2e bash
# NOTE: to list available images:
#   $ docker images
# NOTE: to run the images:
#   $ docker run -i IMAGE_HASH
# NOTE: to run the docker on prepared system (from src root)
#   $ docker build .
# NOTE: if you have your permissions denied, try (from src root)
#   $ sudo -u `whoami` docker build .

RUN apt-get update && apt-get upgrade --yes

# refresh + essentials
RUN apt-get update \
    && apt-get install apt-utils \
    && apt-get install --yes wget git curl bash vim

# without this Git will fail on any secure connections
# NOTE: the http(s)_proxy envars are set from the Docker
#   host configuration (see ~/.docker/config.json file on host)
RUN git config --global http.proxy ${http_proxy}
RUN git config --global https.proxy ${https_proxy}

# Build tools
RUN apt-get install --yes autoconf libtool build-essential

# Current OS sources
#RUN apt-get install --yes linux-image-unsigned-$(uname -r)

# NOTE: following doesn't work, cause the running kernel differs
#   from what is provided
#RUN apt-get install --yes linux-headers-$(uname -r)
# NOTE: using one of available instead
RUN apt-get install --yes linux-headers-5.15.0-25-generic

# And now the ICCom and its build itself using the
# ICCom source which contains our Dockerfile
RUN rm -rf /repos/iccom/ && mkdir -p /repos/iccom

# add only for the container, not for an image
WORKDIR /repos/iccom/
COPY . .
# NOTE: for the reason above: using not the proper line below,
#   but one below it, with explicit headers version, which is only
#   available
#RUN make -C /lib/modules/`uname -r`/build M=/repos/iccom
RUN make -C /lib/modules/5.15.0-25-generic/build M=/repos/iccom
