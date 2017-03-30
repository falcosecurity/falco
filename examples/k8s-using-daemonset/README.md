# Example K8s Services for Falco

The yaml file in this directory installs the following:
 - Open Source Falco, as a DaemonSet. Falco is configured to communicate with the K8s API server via its service account, and changes its output to be K8s-friendly. It also sends to a slack webhook for the `#demo-falco-alerts` channel on our [public slack](https://sysdig.slack.com/messages/demo-falco-alerts/).
 - The [Falco Event Generator](https://github.com/draios/falco/wiki/Generating-Sample-Events), as a deployment that ensures it runs on exactly 1 node.
