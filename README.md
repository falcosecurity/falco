# Digwatch: activity monitoring with sysdig

## Build and run instructions

_Note:_ This is not yet set up to be propertly packaged and installed. For now, running digwatch means building it and installing it manually on the host where you want to run it.


### Building
Clone this repo in a directory that also contains the sysdig source repo. The result should be something like:

```
22:50 vagrant@vagrant-ubuntu-trusty-64:/sysdig
$ pwd
/sysdig
22:50 vagrant@vagrant-ubuntu-trusty-64:/sysdig
$ ls -la
total 20
drwxr-xr-x  1 vagrant vagrant  306 Feb 16 23:06 .
drwxr-xr-x 25 root    root    4096 Feb 18 19:24 ..
drwxr-xr-x  1 vagrant vagrant  680 Jan 23 19:32 agent
drwxr-xr-x  1 vagrant vagrant  238 Feb 21 21:44 digwatch
drwxr-xr-x  1 vagrant vagrant  646 Feb 21 17:41 sysdig
```

create a build dir, then setup cmake and run make from that dir:

```
$ mkdir build
$ cd build
$ cmake ..
$ make
```

as a result, you should have a digwatch executable `build/userspace/digwatch/digwatch`.


### Running

Set the path of the digwatch lua directory in the env var `DIGWATCH_LUA_DIR`:

`export DIGWATCH_LUA_DIR=/sysdig/digwatch/userspace/digwatch/lua/`

(this is just for the manually-built version; the packaged/installed version will not need such an env var).


Create a file with some [digwatch rules](Rule-syntax-and-design). For example:
```
write: (syscall.type=write and fd.typechar=f) or syscall.type=mkdir or syscall.type=creat or syscall.type=rename
interactive: proc.pname = bash or proc.pname = sshd
write and interactive and fd.name contains sysdig
write and interactive and fd.name contains .txt
```



Let's assume you called that file rules.txt. Now you can run digwatch like so:

`./userspace/digwatch/digwatch rules.txt`

And you will see an output event for any interactive process that touches a file with "sysdig" or ".txt" in its name!











