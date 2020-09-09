# Falco fargate support

## Summary

This is a proposal on how to adress deployment of falco in a fargate environment.

Fargate is a serverless runtime offered by AWS. It is used to run docker images without directly provisioning the 
server resources required by the container itself.

The intent is to propose a new project which allows us to wrap existing docker images when deploying to fargate.

## Motivation 

We want to run falco inside fargate containers.

By creating a new project (Kilt) - that takes care of including misc binaries as wrappers we will be able to add 
support for deploying to fargate in a flexible and extensible manner, paving the way to other OSS tools to do the same 
(example: log capture implementations).

## Goals

- Offer an easy mechanism to include falco in fargate containers
- Offer automation when using cloud formation
- Offer automation when using EKS

## Non-Goals

- Automating deployments via API
- Migrating existing task definitions to include fargate

## Proposal

There are 3 main deployment methods when using vanilla AWS: 
- *ECS deployment via API (also UI)* - This deployment type is the hardest to automate. We will offer instructions on how to 
alter the task definition to add falco. We can do a migration tool for existing task definitions but this is not the 
goal of this project
- *ECS deployment via Cloud Formation* - We will offer a cloud formation macro to automatically alter task definitions
in a CFN template with `Transform:${MacroName}`
- *EKS deployment* - We will offer an EKS Admission Controller Mutating Webhook that will alter pods adding falco


### Components
- *kilt-cfn* (PoC ready) - A lambda that patches aws task definitions and can be registered as a macro
- *kilt-run* (WIP) - The new entrypoint of the docker container that we patch. It will exec falco and the original entry
point
- *kilt-eks* (TBD) - A service that listens for webhooks and alters pod resources as they are creating adding kilt-run 
and falco


## Workflow
### Preparation
We prepare and publish a docker image containing kilt-run and falco. The contents would be the following:
```
/kilt/run - kilt-run binary
/kilt/init - an init replacement
/kilt/run.cfg - configuration for launching software in background
/kilt/falco - static binary for software to be launched
/kilt/* - falco configs?
```
### Kilt Installation
#### What the final user sees
User downloads a cloud formation template distributed by us and executes it on the account. 
User then adds the `Falco::FargateSupport` transform to the Cloud Formation templates that wants monitored and runs a 
deploy.

#### Behind the scenes
The CFN installer downloads the `kilt` binary and sets it up as an `AWS::Lambda`. A 
[CFN Macro](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-macros.html) is registered for 
`Falco::FargateSupport`

### Kilt Transformation
#### What the final user sees
totally transparent
#### Behind the scenes
The kilt lambda is invoked on each stack creation/update referencing the macro. It finds all fargate task definitions
in the template and applies the following patches:
* add a container containing falco and kilt-run (from Preparation section) to the list of containers
* alter all other containers in the task
  * add VolumesFrom directive to mount `/kilt/` from the kilt container
  * set kilt-run as entrypoint
  * set original entrypoint + command as the command
  * add metadata in environment variables (TBD)
  
### Runtime
#### What the final user sees
final user sees logs from falco in cloudwatch

#### Behind the scenes
`kilt-run` is invoked. It forks and execs falco as specified in `run.cfg`. The launch is wrapped with `/kilt/init` 
binary which is actually [dumb-init](https://github.com/Yelp/dumb-init). 


## Design

### kilt-cfn
A aws lambda written in go that receives fragments of template to transform. Does not need any permissions. See Kilt 
Transformation for the alterations applied

### kilt-run
A static executable that reads `run.cfg` and `exec`s into init and falco.

### kilt-eks
A webservice to be deployed to accept admission controller webhooks

## To be decided
* how to deploy kilt-eks
* config format - is TOML fine?
* kilt-run single binary vs include `dumb-init`
* other types of deployments?