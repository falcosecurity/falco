#!/bin/bash
set -eu

SCRIPT=$(readlink -f $0)
BASEDIR=$(dirname $SCRIPT)

FALCO=$1
BUILDDIR=$(dirname $FALCO)

# Load the built kernel module by hand
insmod $BUILDDIR/../../driver/sysdig-probe.ko

# For now, simply ensure that falco can run without errors.
FALCO_CMDLINE="$FALCO -c $BASEDIR/../falco.yaml -r $BASEDIR/../rules/falco_rules.yaml"
echo "Running falco: $FALCO_CMDLINE"
$FALCO_CMDLINE > $BASEDIR/falco.log 2>&1 &
FALCO_PID=$!
echo "Falco started, pid $FALCO_PID"
sleep 10
if kill -0 $FALCO_PID > /dev/null 2>&1; then
    echo "Falco ran successfully"
    kill $FALCO_PID
    ret=0
else
    echo "Falco did not start successfully. Full program output:"
    cat $BASEDIR/falco.log
    ret=1
fi

exit $ret
