# Falco userspace launch support

## Summary

This is a proposal on how to address deployment of Falco in a userspace
 environment.

There has been a rise in popularity of serverless architectures that are 
managed and make kernel instrumentation impossible. This makes it quite hard to
monitor the runtimes. This project is about defining a patching language/definition
that allows Falco to be deployed alongside a container in userspace.

## Motivation 

We want to run Falco inside containers without access to kernel space.

By creating a new project (Kilt) - that defines a patching/deployment procedure 
it is possible to deploy Falco in different userspace environments (k8s, cloud 
formation, etc)

The project consists of a definition for recipes to include binaries and alter 
containers, a library to process recipes and runtimes that execute the recipes 
on supported platforms.

## Goals

- Offer a definition format for patching/deploying Falco along user containers
- Offer a golang library that parses and executes recipes
- Define a patching file for Falco

## Possible runtimes
- Automation when using k8s (Admission Controller Mutating Webhook)
- Automation when using cloud formation (CFN Macro)


## Non-Goals

- Implementing an image patching runtime

## Proposal

The proposal intends to cover the following use cases: 

- *Existing containers outside of K8S* - This deployment type is the hardest to automate. We 
will offer instructions on how to alter the containers to add Falco. We can do 
a migration tool for existing containers but this is not the goal of this
 project. Adding `patch {}` instructions to the file actually offers a way
towards offering this functionality as well

- *K8S* - We will offer a K8S Admission Controller Mutating Webhook that will 
alter pods adding Falco according to patching file

- *K8S-exec* - We will offer a way to execute `patch {}` instructions against 
specific pods

- *Cloud Formation* - We will offer a cloud formation macro to automatically 
alter fargate task definitions in a CFN template



### Components
- *kilt-cfn* (In PR https://github.com/falcosecurity/evolution/pull/40) - A lambda that patches aws task definitions 
and can be registered as a macro
- *kilt-k8s-webhook* (TBD) - A service that listens for webhooks and alters pod
 resources as they are created
- *kilt-k8s-exec* - CLI to patch existing k8s pods.


### Kilt definition config format
We decided to go with HOCON for the kilt definition file as it is very flexible and not obnoxious to write (it is less sensible to whitespace than YAML, but 
can translate to JSON as well).

## Workflow
### Preparation (done by Falco maintainers)
We prepare and publish a docker image containing Falco. The contents would be 
the following:

```
/falco/falco - falco binary
/falco/pdig - ptrace-based instrumentation (userspace)
/falco/* - falco configs? other binaries?
```

We also provide a file called `kilt.cfg` which looks like:

```
 build {
    entrypoint: [ /falco/pdig ] ${original.entrypoint}
    mount: [
        {
            image: "falco/falco:latest"
            volumes: /falco
            entrypoint: /falco/waitforever
        }
    ]
	environment:
		FALCO_METADATA: "image="${original.image}",name="${original.name}
}
runtime {
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
    exec: [
        /falco/pdig -p 1
    ]
}
```

### Cloud Formation User Workflow
#### What the final user sees
User downloads an installer done by us and executes it.
User then adds the newly created macro as a transform to the Cloud Formation templates that wants monitored and runs
 a deploy.
 
This step can also be used to distribute upgrades for Falco and Kilt runtimes.

#### Behind the scenes
The installer downloads the `kilt` binary and sets it up as an
 `AWS::Lambda`. A [CFN Macro](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-macros.html)
 is registered with a name provided by the user (example: `FalcoMacro`).

### Kilt Transformation

#### What the final user sees
User creates a new stack/upgrades an existing stack with a CFN template that includes `Transform: ${MacroName}`
 at root level.

#### Behind the scenes
The kilt-cfn lambda is invoked on each stack creation/update referencing the
 macro. It finds all fargate task definitions in the template and applies the 
patches defined in `kilt.cfg` specified during macro installation.
  
### Runtime
#### What the final user sees
final user sees logs from Falco in cloudwatch

#### Behind the scenes
pdig is invoked. It forks and execs Falco and original command.


## Design

### kilt-cfn
A aws lambda written in go that receives fragments of template to transform. 
Does not need any permissions. Will execute instructions in the provided 
`kilt.cfg` file. Can only interpret directives under `build`

### kilt-k8s-webhook
A webservice to be deployed to accept admission controller webhooks. 
Applies only `build` directives. The service will run under k8s and will be 
deployed via YAML.

### kilt-k8s-exec
A CLI that uses local kubectl to instrument containers. Will only interpret 
`runtime` directives

## Actions
* create a kilt repository
* create a kilt-definitions repository

