# The file describes the testing sequence of the SymSPI driver
# * builds and tests SymSPI in various configurations

FROM bosch-linux-full-duplex-interface:latest

# NOTE: to purge the Docker unused files use:
#   $ docker system prune -a
# NOTE: to run shell on the image:
#   $ docker run -it YOUR_IMAGE_NAME sh
#   $ sudo -u YOUR_USERNAME docker run -it YOUR_IMAGE_HASH bash
#   FOR EXAMPLE:
#     $ sudo -u `whoami` docker run -it c8c279906c2e bash
# NOTE: to list latest available images:
#   $ sudo -u `whoami` docker images | head
# NOTE: to run the images:
#   $ docker run -i IMAGE_HASH
# NOTE: to run the docker on prepared system (from src root)
#   $ docker build .
# NOTE: if you have your permissions denied, try (from src root)
#   $ sudo -u `whoami` docker build .

########## Here we go: build and test

ENV repo_path=/repos/linux-iccom
RUN rm -rf ${repo_path} && mkdir -p ${repo_path}

# add only for the container, not for an image
WORKDIR ${repo_path}
COPY . .

### TEST BUILDS CONFIGURATIONS ###

# Base (default) version
ARG kernel_version=5.15.0-25-generic
ARG kernel_source_dir=/lib/modules/${kernel_version}/build

# Default build
RUN make -C ${kernel_source_dir} M=${repo_path} \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_CHECK_SIGNATURE=n \
    && make KVER=${kernel_version} install \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_MODULE_SIG_ALL=n \
    && make KVER=${kernel_version} uninstall \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_MODULE_SIG_ALL=n \
    && rm -rf ${repo_path}/*
COPY . .

# Workqueue - use the system WQ
RUN make -C ${kernel_source_dir} M=${repo_path} \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM \
        CONFIG_CHECK_SIGNATURE=n \
    && make KVER=${kernel_version} install \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM \
        CONFIG_MODULE_SIG_ALL=n \
    && make KVER=${kernel_version} uninstall \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM \
        CONFIG_MODULE_SIG_ALL=n \
    && rm -rf ${repo_path}/*
COPY . .

# Workqueue - use the system high prio WQ
RUN make -C ${kernel_source_dir} M=${repo_path} \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM_HIGHPRI \
        CONFIG_CHECK_SIGNATURE=n \
    && make KVER=${kernel_version} install \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM_HIGHPRI \
        CONFIG_MODULE_SIG_ALL=n \
    && make KVER=${kernel_version} uninstall \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=SYSTEM_HIGHPRI \
        CONFIG_MODULE_SIG_ALL=n \
    && rm -rf ${repo_path}/*
COPY . .

# Workqueue - use the private highprio WQ
RUN make -C ${kernel_source_dir} M=${repo_path} \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=PRIVATE \
        CONFIG_CHECK_SIGNATURE=n \
    && make KVER=${kernel_version} install \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=PRIVATE \
        CONFIG_MODULE_SIG_ALL=n \
    && make KVER=${kernel_version} uninstall \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_WORKQUEUE_MODE=PRIVATE \
        CONFIG_MODULE_SIG_ALL=n \
    && rm -rf ${repo_path}/*
COPY . .


# Debug with embedded defaults
RUN make -C ${kernel_source_dir} M=${repo_path} \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_DEBUG=y \
        CONFIG_CHECK_SIGNATURE=n \
    && make KVER=${kernel_version} install \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_DEBUG=y \
        CONFIG_MODULE_SIG_ALL=n \
    && make KVER=${kernel_version} uninstall \
		CONFIG_BOSCH_ICCOM=m \
        CONFIG_BOSCH_ICCOM_DEBUG=y \
        CONFIG_MODULE_SIG_ALL=n \
    && rm -rf ${repo_path}/*
COPY . .
