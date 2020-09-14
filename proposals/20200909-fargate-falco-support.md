# Falco userspace launch support

## Summary

This is a proposal on how to adress deployment of falco in a userspace
 environment.

There has been a rise in popularity of serverless architectures that are 
managed and make kernel instrumentation impossible. This makes it quite hard to
monitor the runtimes. This project is about defining a patching language/definition
that allows falco to be deployed alongside a container in userspace.

## Motivation 

We want to run falco inside containers without access to kernel space.

By creating a new project (Kilt) - that defines a patching/deployment procedure 
it is possible to deploy falco in different userspace environments (k8s, cloud 
formation, etc) 

## Goals

- Offer a definition format for patching/deploying falco along user containers
- Define a patching file for falco
- Offer automation when using k8s
- Offer automation when using cloud formation


## Non-Goals

- Automating deployments done outside of goals

## Proposal

There are 3 main deployment methods when using vanilla AWS: 

- *Existing containers outside of K8S* - This deployment type is the hardest to automate. We 
will offer instructions on how to alter the containers to add falco. We can do 
a migration tool for existing containers but this is not the goal of this
 project. Adding `patch {}` instructions to the file actually offers a way
towards offering this functionality as well

- *K8S* - We will offer a K8S Admission Controller Mutating Webhook that will 
alter pods adding falco according to patching file

- *K8S-exec* - We will offer a way to execute `patch {}` instructions against 
specific pods

- *Cloud Formation* - We will offer a cloud formation macro to automatically 
alter fargate task definitions in a CFN template



### Components
- *kilt-cfn* (PoC ready) - A lambda that patches aws task definitions and can
 be registered as a macro
- *kilt-k8s-webhook* (TBD) - A service that listens for webhooks and alters pod
 resources as they are created
- *kilt-k8s-exec* - CLI to patch existing k8s pods.


## Workflow 
### Preparation
We prepare and publish a docker image containing falco. The contents would be 
the following:

```
/falco/falco - falco binary
/falco/pdig - ptrace-based instrumentation
/falco/* - falco configs?
```

We also provide a file called `kilt.cfg` which looks like:

```
 deploy {
    entrypoint: [ /falco/pdig ] ${original.entrypoint}
    mount: [
        {
            image: "falco/falco:latest"
            volume: /falco
            entrypoint: /falco/waitforever
        }
    ]
	environment:
		FALCO_METADATA: "image="${original.image}",name="${original.name}
}
patch {
    upload: [
        {
            url: "http://blah"
            as: "/falco/falco"
        }
        {
            file: "local/path/to/pdig"
            as: "/falco/pdig"
        }
        {
            payload: "base64payload" //or directly text
            as: "/falco/falco.cfg"
        }
    ]
    background_exec: [
        /falco/pdig -p 1
    ]
}
```

### Cloud Formation User Workflow
#### What the final user sees
User downloads a cloud formation template distributed by us and executes it on
 the AWS account. 
User then adds the newly created macro as a transform to the Cloud Formation
 templates that wants monitored and runs a deploy.

#### Behind the scenes
The CFN installer downloads the `kilt` binary and sets it up as an
 `AWS::Lambda`. A [CFN Macro](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-macros.html)
 is registered with a name provided by the user.

### Kilt Transformation

#### What the final user sees
totally transparent

#### Behind the scenes
The kilt-cfn lambda is invoked on each stack creation/update referencing the
 macro. It finds all fargate task definitions in the template and applies the 
patches defined in `kilt.cfg`
  
### Runtime
#### What the final user sees
final user sees logs from falco in cloudwatch

#### Behind the scenes
pdig is invoked. It forks and execs falco and original command.


## Design

### kilt-cfn
A aws lambda written in go that receives fragments of template to transform. 
Does not need any permissions. Will execute instructions in the provided 
`kilt.cfg` file. Can only interpret directives under `deploy`

### kilt-k8s-webhook
A webservice to be deployed to accept admission controller webhooks. 
Applies only `deploy` directives. The service will run under k8s and will be 
deployed via YAML.

### kilt-k8s-exec
A CLI that uses local kubectl to instrument containers. Will only interpret 
`patch` directives

## To be decided
* config format - is [HOCON](https://github.com/lightbend/config/blob/master/HOCON.md) fine?