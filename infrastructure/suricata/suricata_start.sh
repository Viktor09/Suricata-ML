#!/bin/bash
set -e

rm -f /var/log/suricata/eve.json
touch /var/log/suricata/eve.json

suricata -i vl-mirror -c /etc/suricata/suricata.yaml &
SURICATA_PID=$!

sleep 5

tail -n 0 -F /var/log/suricata/eve.json | jq -Rc '
  fromjson?
  | select(.event_type? == "alert")
'

wait $SURICATA_PID
