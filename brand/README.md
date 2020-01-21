<p align="center"><img src="brand/primary-logo.png" width="360"></p>
<p align="center"><b>Cloud Native Runtime Security.</b></p>

# Falco Branding Guidelines

This document describes The Falco Project's branding guidelines, language, and message.

Content in this document can be used to publically share about Falco.



### Logo

There are 3 logos available for use in this directory. Use the primary logo unless required otherwise due to background issues, or printing.

The Falco logo is Apache 2 licensed and free to use in media and publication for the CNCF Falco project.

### Slogan

> Cloud Native Runtime Security

### What is Falco?

Falco is a Runtime Security project originally built by Sysdig, Inc.
Falco was donated to the CNCF in October 2018.
The CNCF now owns The Falco Project.

### What is Runtime Security?

Runtime Security refers to an approach to securing a computer system.
With Runtime Security an operator deploys **both** prevention tooling (access control, policy enforcement, etc) along side detection tooling (systems observability, anomaly detection, etc).
Runtime Security is the practice of using detection tooling to detect unwanted behavior, such that it can then be prevented using prevention techniques.
Runtime Security is a last line of defense, and useful in scenarios where prevention tooling either was unaware of an exploit or attack vector, or when defective applications are ran in even the most secure environment.

### What does Falco do?

Falco consumes signals from the Linux kernel, and container management tools such as Docker and Kubernetes.
Falco parses the signals and asserts them against security rules.
If a rule has been violated, Falco triggers an alert. 

### How does Falco work?

Falco uses eBPF (or on older systems a kernel module) to trace syscall events in the kernel.
Falco enriches these kernel events with information about containers running on the system.
These other input streams come from various input streams such as the Docker socket, the Kubernetes API server, and the Kubernetes audit log.
At runtime, Falco will reason about these events and assert them against security rules.
Based on the violation, and Falco's configuration an alert is triggered which can start events downstream.

### Writing about Falco

#### Yes

Notice the capitalization of the following terms.

 - The Falco Project
 - Falco
 - Runtime Security

#### No

 - falco
 - the falco project
 - the Falco project
 - runtime security 

### Encouraged Phrasing

Below are phrases that the project has reviewed, and found to be effective ways of messaging Falco's value add.

##### Falco as a factory

This term refers to the concept that Falco is a stateless processing engine. A large amount of data comes into the engine, but maticulously crafted security alerts come out.

##### The engine that powers...

Falco ultimately is a security engine. It reasons about signals coming from a system at runtime, and can alert if an anomaly is detected.

##### Anomaly detection

This refers to an event that occurs with something unsual, concerning, or odd occurs.
We can associate anomalies with unwanted behavior, and alert in their presence.

###### Detection tooling

Falco does not prevent unwanted behavior.
Falco however alerts when unusual behavior occurs.
This is commonly referred to as **detection** or **forensics**.

### Key benefits

 - Complimentary to prevention tooling
 - Last line of defense against new exploits and attack vectors
 - Last line of defense against malicious applications, or vulnerable applications
 