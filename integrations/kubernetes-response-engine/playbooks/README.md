# Playbooks

Following [owasp ideas](https://owaspsummit.org/Working-Sessions/Security-Playbooks/index.html),
playbooks are workflows and prescriptive instructions on how to handle specific
Security activities or incidents.

Being more specific, playbooks are actions that are going to be executed when
Falco finds a weird behavior in our Kubernetes cluster. We have implemented
them with Python and we have found that several Serverless concepts fits well
with playbooks, so we use [Kubeless](https://kubeless.io/) for its deployment.

## Requirements

* A working Kubernetes cluster
* [kubeless cli executable](https://kubeless.io/docs/quick-start/)
* Python 3.6
* pipenv

## Deploying a playbook

Deploying a playbook involves a couple of components, the function that is going
to be with Kubeless and a trigger for that function.

We have automated those steps in a generic script *deploy_playbook* who packages
the reaction and its dependencies, uploads to Kubernetes and creates the kubeless
trigger.

```
./deploy_playbook -p slack -e SLACK_WEBHOOK_URL="https://..." -t "falco.error.*" -t "falco.info.*"
```

### Parameters

* -p: The playbook to deploy, it must match with the top-level script. In this
    example *slack.py* that contains the wiring between playbooks and Kubeless
    functions

* -e: Sets configuration settings for Playbook. In this case the URL where we
    have to post messages. You can specify multiple *-e* flags.

* -t: Topic to susbcribe. You can specify multiple *-t* flags and a trigger
    will be created for each topic, so when we receive a message in that topic,
    our function will be ran. In this case, playbook will be run when a
    falco.error or falco.info alert is raised.

### Kubeless 101

Under the hood, there are several useful commands for checking function state with kubeless.


We can retrieve all functions deployed in our cluster:
```
kubeless function list
```

And we can see several interesting stats about a function usage:
```
kubeless function top
```

And we can see bindings between functions and NATS topics:
```
kubeless trigger nats list
```

### Undeploying a function

You have to delete every component using kubeless cli tool.

Generally, it takes 2 steps: Remove the triggers and remove the function.

Remove the triggers:
```
kubeless trigger nats delete trigger-name
```

If you have deployed with the script, trigger-name look like:
*falco-<playbook>-trigger-<index>* where index is the index of the topic created.
Anyway, you can list all triggers and select the name.


Remove the function:
```
kubeless function delete function-name
```

If you have deployed with the script, the function name will start with *falco-<playbook>*,
but you can list all functions and select its name.

## Testing

One of the goals of the project was that playbooks were tested.

You can execute the tests with:

```
pipenv --three install -d
export KUBERNETES_LOAD_KUBE_CONFIG=1
pipenv run mamba --format=documentation
```

The first line install development tools, which includes test runner and assertions.
The second one tells Kubernetes Client to use the same configuration than kubectl and
the third one runs the test.

The tests under *specs/infrastructure* runs against a real Kubernetes cluster,
but the *spec/reactions* can be run without any kind of infrastructure.

## Available Playbooks

### Delete a Pod

This playbook kills a pod using Kubernetes API

```
./deploy_playbook -p delete -t "falco.notice.terminal_shell_in_container"
```

In this example, everytime we receive a *Terminal shell in container* alert from
Falco, that pod will be deleted.

### Send message to Slack

This playbook posts a message to Slack

```
./deploy_playbook -p slack -t "falco.error.*" -e SLACK_WEBHOOK_URL="https://..."
```

#### Parameters

* SLACK_WEBHOOK_URL: This is the webhook used for posting messages in Slack

In this example, when Falco raises an error we will be notified in Slack

### Taint a Node

This playbook taints the node which where pod is running.

```
$ ./deploy_playbook -p taint -t “falco.notice.contact_k8s_api_server_from_container”
```

#### Parameters:
* TAINT_KEY: This is the taint key. Default value: ‘falco/alert’
* TAINT_VALUE: This is the taint value. Default value: ‘true’
* TAINT_EFFECT: This is the taint effect. Default value: ‘NoSchedule’

In this example, we avoid scheduling in the node which originates the Contact
K8S API server from container.  But we can use a more aggresive approach and
use -e TAINT_EFFECT=NoExecute

### Network isolate a Pod

This reaction denies all ingress/egress traffic from a Pod. It's intended to
be used with Calico or other similar projects for managing networking in
Kubernetes.

```
./deploy_playbook -p isolate -t “falco.notice.write_below_binary_dir” -t “falco.error.write_below_etc”
```

So as soon as we notice someone wrote under /bin (and additional binaries) or
/etc, we disconnect that pod. It's like a trap for our attackers.

### Create an incident in Demisto

This playbook creates an incident in Demisto

```
./deploy_playbook -p demisto -t "falco.*.*" -e DEMISTO_API_KEY=XxXxxXxxXXXx -e DEMISTO_BASE_URL=https://..."
```

#### Parameters

* DEMISTO_API_KEY: This is the API key used for authenticating against Demisto. Create one under settings -> API keys
* DEMISTO_BASE_URL: This is the base URL where your Demisto server lives on. Ensure there's no trailing slash.
* VERIFY_SSL: Verify SSL certificates for HTTPS requests. By default is enabled.

In this example, when Falco raises any kind of alert, the alert will be created in Demisto
