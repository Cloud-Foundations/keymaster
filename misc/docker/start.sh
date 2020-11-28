#!/bin/sh

# Copy config file if it doesn't exist so that the app can start
if [ ! -f /etc/keymaster/config.yml ] ; then
  echo "Generate Configs"
  exit 1
 fi

# Run app
/app/keymasterd -config /etc/keymaster/config.yml -alsoLogToStderr

echo ""
echo "keymasterd has exited."
echo "Exiting."
