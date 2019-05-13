% falco (1) Container Image Pages
% Falco Team
% June, 2017

# NAME
falco \- Container Native runtime security

# DESCRIPTION
Falco is an open source project for intrusion and abnormality detection for Cloud Native platforms. See Falco website for more information: http://falco.org/

# EXAMPLE
    docker run -d --name falco --restart always --privileged --net host --pid host -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro --shm-size=350m registry.connect.redhat.com/sysdig/falco

# AUTHORS
Falco Team
