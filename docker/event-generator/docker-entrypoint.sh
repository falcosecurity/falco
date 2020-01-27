#!/bin/bash

CMD=${1:-syscall}

shift

set -euo pipefail

if [[ "$CMD" == "syscall" ]]; then
    /usr/local/bin/event_generator
elif [[ "$CMD" == "k8s_audit" ]]; then
    . k8s_event_generator.sh
elif [[ "$CMD" == "bash" ]]; then
    bash
else
    echo "Unknown command. Can be one of"
    echo "   \"syscall\": generate falco syscall-related activity"
    echo "   \"k8s_audit\": generate falco k8s audit-related activity"
    echo "   \"bash\": spawn a shell"
    exit 1
fi
