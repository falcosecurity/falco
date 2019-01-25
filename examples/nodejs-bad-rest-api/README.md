# Demo of falco with bash exec via poorly designed REST API.

## Introduction

This example shows how a server could have a poorly designed API that
allowed a client to execute arbitrary programs on the server, and how
that behavior can be detected using Sysdig Falco.

`server.js` in this directory defines the server. The poorly designed
API is this route handler:

```javascript
router.get('/exec/:cmd', function(req, res) {
    var output = child_process.execSync(req.params.cmd);
    res.send(output);
});

app.use('/api', router);
```

It blindly takes the url portion after `/api/exec/<cmd>` and tries to
execute it. A horrible design choice(!), but allows us to easily show
Sysdig falco's capabilities.

## Demo architecture

### Start everything using docker-compose

From this directory, run the following:

```
$ docker-compose -f demo.yml up
```

This starts the following containers:

* express_server: simple express server exposing a REST API under the endpoint `/api/exec/<cmd>`.
* falco: will detect when you execute a shell via the express server.

### Access urls under `/api/exec/<cmd>` to run arbitrary commands.

Run the following commands to execute arbitrary commands like 'ls', 'pwd', etc:

```
$ curl http://localhost:8181/api/exec/ls

demo.yml
node_modules
package.json
README.md
server.js
```

```
$ curl http://localhost:8181/api/exec/pwd

.../examples/nodejs-bad-rest-api
```

### Try to run bash via `/api/exec/bash`, falco sends alert.

If you try to run bash via `/api/exec/bash`, falco will generate an alert:

```
falco          | 22:26:53.536628076: Warning Shell spawned in a container other than entrypoint (user=root container_id=6f339b8aeb0a container_name=express_server shell=bash parent=sh cmdline=bash )
```
