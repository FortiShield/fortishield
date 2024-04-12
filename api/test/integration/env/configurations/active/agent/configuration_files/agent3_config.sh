#!/usr/bin/env bash

# Disable active-response for agent 003
if [ "$HOSTNAME" == "fortishield-agent3" ]; then
  sed -i "/<active-response>/{n;s/no/yes/}" /var/ossec/etc/ossec.conf
fi
