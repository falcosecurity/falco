# Kubernetes Response Engine for Sysdig Falco

The goal of this project is to create a response engine for Kubernetes which is
able to execute playbooks to different types of security threats in our
cointainer fleet alerted by Falco.

There are several principles which guides our decisions (in no particular order):

* Real time responses to a security threat: We need to react as soon as possible.
* Deployment independence: Each playbook is independent of others.
* Open Source Software: We want to use and promote OSS.
* Write rock solid code: Each playbook is tested.

## Alert lifecycle outline

An alert travels by our system, these are the typical stages for an alert:

1. *Falco* detects an alert in one container which belongs to our fleet
2. *Falco* sends the alert to *NATS* using a topic compound by "falco.<severity>.<rule_name_slugified>"
3. *NATS* delivers message to its subscribers through *Kubeless* infrastructure
4. *Kubeless* receives the alert and pass it to inner *Playbook*
6. *Playbook* performs its inner action: Stopping the container, Sending an alert to Slack ...

## Glossary

* *Alert*: Falco sends alerts
* *Playbook*: Each piece of Python code which is run when an alert is received
