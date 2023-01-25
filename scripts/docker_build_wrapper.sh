#!/bin/bash

set -e

# This script is a docker wrapper to use the
# host machine credentials to access the repos. Basically
# it is the same docker-build command with some options
# already set to allow docker to grab the credentials from the
# host sytem via ssh-agent.
#
# Synopsis:
#   docker_build_wrapper.sh DOCKER_BUILD_PARAMETERS
#
# NOTE: DOCKER_BUILD_PARAMETERS are the parameters for the
#   ordinary 'docker build' command, see docker help for this.


# The first part of the script exports the host credentials to
# the ssh-agent in such a way, that they are available to the docker.

LIGHT_BLUE='\033[1;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

function log()
{
    echo -e $@
}

function cleanup()
{
    echo -e "${NC}"
}

trap cleanup EXIT

#### SSH keys exposing section

echo "First: adding the SSH keys to ssh-agent, to make docker"\
     " capable to pull from the ssh repos."

agents_count=$(ps -aux | grep ssh-agent | grep -v grep | wc -l)

if [ ${agents_count} == 0 ]; then
    echo "Launching the ssh-agent to make your native keys available"\
         " to the docker build."
    eval $(ssh-agent)
    sleep 2
else
    echo "SSH agent is already launched."
fi

# ensuring that socket is available even if we didn't start the agent
# or if the value is outdated.
if ! ssh-add -l; then
    log "${YELLOW}Seems that you don't have a SSH_AUTH_SOCK broken. Fixing.${NC}"

    for sk in `ls /tmp/ssh-*/agent.*`; do
        export SSH_AUTH_SOCK="${sk}"
        if ssh-add -l; then
            log "ssh-agent ${GREEN}fixed${NC}. Resuming."
            break;
        fi
    done
    if ! ssh-add -l; then
        log "${YELLOW}Sorry, ${RED}failed to fix ssh-agent. ${YELLOW}Aboring.${NC}"
        return 2
    fi
fi

echo "Additing ssh keys to the ssh-agent..."

for key in ${HOME}/.ssh/*; do
    if ! [ -f "${key}" ]; then continue; fi
    if [[ "${key}" =~ ^.*\.pub$ ]]; then continue; fi
    if [[ "${key}" =~ ^.*known_hosts$ ]]; then continue; fi
    if [[ "${key}" =~ ^.*authorized_keys$ ]]; then continue; fi
    if [[ "${key}" =~ ^.*config$ ]]; then continue; fi
    echo "Adding the key to ssh-agent: ${key}"
    ssh-add "${key}" || true
done

echo
echo "The list of available ssh keys:"
echo -e "===== Available keys =====${GREEN}"
ssh-add -l
echo -e "${NC}=== Available keys EOF ==="
echo

keys_count=$(ssh-add -l 2>/dev/null | wc -l)

if [ ${keys_count} == 0 ]; then
    echo "ERROR: you have no keys defined for your ssh-agent." \
         " This will make impossible to docker to pull from ssh-driven" \
         " protected repositories."
    exit 1
fi

echo '**********************************************'
echo -e "${YELLOW}NOTE: if build fails, please check first of all if you have " \
     "added all relevant ssh keys (use 'ssh-add PATH_TO_KEY' command to" \
     " add them).${NC}"
echo '**********************************************'
echo

# The second part of the script is the docker wrapper itself

docker build --secret id=known_hosts,src=${HOME}/.ssh/known_hosts \
             --ssh default=${SSH_AUTH_SOCK}                       \
             "$@"
