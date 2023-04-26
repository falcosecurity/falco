<p align="center"><img src="primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

# Falco Branding Guidelines

Falco is an open source security project whose brand and identity are governed by the [Cloud Native Computing Foundation](https://www.linuxfoundation.org/legal/trademark-usage).

This document describes the official branding guidelines of The Falco Project. Please see the [Falco Branding](https://falco.org/falco-brand) page on our website for further details.

### What is Runtime Security?

Runtime security refers to an approach to preventing unwanted activity on a computer system. 
With runtime security, an operator deploys **both** prevention tooling (access control, policy enforcement, etc) along side detection tooling (systems observability, anomaly detection, etc).
Runtime security is the practice of using detection tooling to detect unwanted behavior, such that it can then be prevented using prevention techniques.
Runtime security is a holistic approach to defense, and useful in scenarios where prevention tooling either was unaware of an exploit or attack vector, or when defective applications are ran in even the most secure environment.

### What does Falco do?

Falco consumes signals from the Linux kernel, and container management tools such as Docker and Kubernetes.
Falco parses the signals and asserts them against security rules.
If a rule has been violated, Falco triggers an alert. 

### How does Falco work?

Falco traces kernel events and reports information about the system calls being executed at runtime.
Falco leverages the extended berkeley packet filter (eBPF) which is a kernel feature implemented for dynamic crash-resilient and secure code execution in the kernel. 
Falco enriches these kernel events with information about containers running on the system.
Falco also can consume signals from other input streams such as the containerd socket, the Kubernetes API server and the Kubernetes audit log.
At runtime, Falco will reason about these events and assert them against configured security rules.
Based on the severity of a violation an alert is triggered.
These alerts are configurable and extensible, for instance sending a notification or [plumbing through to other projects like Prometheus](https://github.com/falcosecurity/falco-exporter). 

### Benefits of using Falco

 - **Strengthen Security** Create security rules driven by a context-rich and flexible engine to define unexpected application behavior.
 - **Reduce Risk** Immediately respond to policy violation alerts by plugging Falco into your current security response workflows and processes.
 - **Leverage up-to-date Rules** Alert using community-sourced detections of malicious activity and CVE exploits.
    
### Falco and securing Kubernetes

Securing Kubernetes requires putting controls in place to detect unexpected behavior that could be malicious or harmful to a cluster or application(s). 

Examples of malicious behavior include: 

 - Exploits of unpatched and new vulnerabilities in applications or Kubernetes itself. 
 - Insecure configurations in applications or Kubernetes itself. 
 - Leaked or weak credentials or secret material.
 - Insider threats from adjacent applications running at the same layer. 

Falco is capable of [consuming the Kubernetes audit logs](https://kubernetes.io/docs/tasks/debug-application-cluster/falco/#use-falco-to-collect-audit-events).
By adding Kubernetes application context, and Kubernetes audit logs teams can understand who did what.

---

# Glossary 

#### Probe

Used to describe the `.o` object that would be dynamically loaded into the kernel as a secure and stable (e)BPF probe. 
This is one option used to pass kernel events up to userspace for Falco to consume.
Sometimes this word is incorrectly used to refer to a `module`.

#### Module

Used to describe the `.ko` object that would be loaded into the kernel as a potentially risky kernel module.
This is one option used to pass kernel events up to userspace for Falco to consume.
Sometimes this word is incorrectly used to refer to a `probe`.

#### Driver 

The global term for the software that sends events from the kernel. Such as the eBPF `probe` or the `kernel module`.

#### Plugin

Used to describe a dynamic shared library (`.so` files in Unix, `.dll` files in Windows) that conforms to a documented API and allows to extend Falco's capabilities.

#### Falco

The name of the project, and also the name of [the main engine](https://github.com/falcosecurity/falco) that the rest of the project is built on.

#### Sysdig, Inc

The name of the company that originally created The Falco Project, and later donated to the CNCF.

#### sysdig 

A [CLI tool](https://github.com/draios/sysdig) used to evaluate kernel system events at runtime. 

