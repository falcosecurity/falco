# Kubernetes Response Engine for Sysdig Falco

A response engine for Falco that allows to process security events executing playbooks to respond to security threats.

## Architecture

* *[Falco](https://sysdig.com/opensource/falco/)* monitors containers and processes to alert on unexpected behavior. This is defined through the runtime policy built from multiple rules that define what the system should and shouldn't do.
* *falco-nats* forwards the alert to a message broker service into a topic compound by `falco.<severity>.<rule_name_slugified>`.
* *[NATS](https://nats.io/)*, our message broker, delivers the alert to any subscribers to the different topics.
* *[Kubeless](https://kubeless.io/)*, a FaaS framework that runs in Kubernetes, receives the security events and executes the configured playbooks.

## Glossary

* *Security event*: Alert sent by Falco when a configured rule matches the behaviour on that host.
* *Playbook*: Each piece code executed when an alert is received to respond to that threat in an automated way, some examples include:
  - sending an alert to Slack
  - stop the pod killing the container
  - taint the specific node where the pod is running
