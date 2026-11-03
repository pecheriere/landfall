#!/bin/sh
# What the probe and the script ask of Docker, and all the agent needs to start with nothing to
# deploy. Any other question fails, so a test can't pass by way of a Docker that says yes.
case "$*" in
  --version) echo 'Docker version 27.1.1, build 6312585' ;;
  version) echo 'Client: 27.1.1' ;;
  'compose version --short') echo '2.29.1' ;;
  *)
    echo "fake docker doesn't do: $*" >&2
    exit 1
    ;;
esac
