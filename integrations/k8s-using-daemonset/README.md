# Example Kubernetes Daemon Sets for Sysdig Falco

This directory gives you the required YAML files to stand up Sysdig Falco on Kubernetes as a Daemon Set. This will result in a Falco Pod being deployed to each node, and thus the ability to monitor any running containers for abnormal behavior.

The two options are provided to deploy a Daemon Set:
- `k8s-with-rbac` - This directory provides a definition to deploy a Daemon Set on Kubernetes with RBAC enabled.
- `k8s-without-rbac` - This directory provides a definition to deploy a Daemon Set on Kubernetes without RBAC enabled. **This method is deprecated in favor of RBAC-based installs, and won't be updated going forward.**

Also provided:
- `falco-event-generator-deployment.yaml` - A Kubernetes Deployment to generate sample events. This is useful for testing, but note it will generate a large number of events.

## Deploying to Kubernetes with RBAC enabled

Since v1.8 RBAC has been available in Kubernetes, and running with RBAC enabled is considered the best practice. The `k8s-with-rbac` directory provides the YAML to create a Service Account for Falco, as well as the ClusterRoles and bindings to grant the appropriate permissions to the Service Account.

```
k8s-using-daemonset$ kubectl create -f k8s-with-rbac/falco-account.yaml
serviceaccount "falco-account" created
clusterrole "falco-cluster-role" created
clusterrolebinding "falco-cluster-role-binding" created
k8s-using-daemonset$
```

We also create a service that allows other services to reach the embedded webserver in falco, which listens on https port 8765:

```
k8s-using-daemonset$ kubectl create -f k8s-with-rbac/falco-service.yaml
service/falco-service created
k8s-using-daemonset$
```

The Daemon Set also relies on a Kubernetes ConfigMap to store the Falco configuration and make the configuration available to the Falco Pods. This allows you to manage custom configuration without rebuilding and redeploying the underlying Pods. In order to create the ConfigMap you'll need to first need to copy the required configuration from their location in this GitHub repo to the `k8s-with-rbac/falco-config/` directory (please note that you will need to create the /falco-config directory). Any modification of the configuration should be performed on these copies rather than the original files.

```
k8s-using-daemonset$ mkdir -p k8s-with-rbac/falco-config
k8s-using-daemonset$ cp ../../falco.yaml k8s-with-rbac/falco-config/
k8s-using-daemonset$ cp ../../rules/falco_rules.* k8s-with-rbac/falco-config/
k8s-using-daemonset$ cp ../../rules/k8s_audit_rules.yaml k8s-with-rbac/falco-config/
```

If you want to send Falco alerts to a Slack channel, you'll want to modify the `falco.yaml` file to point to your Slack webhook. For more information on getting a webhook URL for your Slack team, refer to the [Slack documentation](https://api.slack.com/incoming-webhooks). Add the below to the bottom of the `falco.yaml` config file you just copied to enable Slack messages.

```
program_output:
  enabled: true
  keep_alive: false
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/see_your_slack_team/apps_settings_for/a_webhook_url"
```

You will also need to enable JSON output. Find the `json_output: false` setting in the `falco.yaml` file and change it to read `json_output: true`. Any custom rules for your environment can be added to into the `falco_rules.local.yaml` file and they will be picked up by Falco at start time. You can now create the ConfigMap in Kubernetes.

```
k8s-using-daemonset$ kubectl create configmap falco-config --from-file=k8s-with-rbac/falco-config
configmap "falco-config" created
k8s-using-daemonset$
```

Now that we have the requirements for our Daemon Set in place, we can create our Daemon Set.

```
k8s-using-daemonset$ kubectl create -f k8s-with-rbac/falco-daemonset-configmap.yaml
daemonset "falco" created
k8s-using-daemonset$
```


## Deploying to Kubernetes without RBAC enabled (**Deprecated**)

If you are running Kubernetes with Legacy Authorization enabled, you can use `kubectl` to deploy the Daemon Set provided in the `k8s-without-rbac` directory. The example provides the ability to post messages to a Slack channel via a webhook. For more information on getting a webhook URL for your Slack team, refer to the [Slack documentation](https://api.slack.com/incoming-webhooks). Modify the [`args`](https://github.com/draios/falco/blob/dev/examples/k8s-using-daemonset/falco-daemonset.yaml#L21) passed to the Falco container to point to the appropriate URL for your webhook.

```
k8s-using-daemonset$ kubectl create -f k8s-without-rbac/falco-daemonset.yaml
```

When running falco via a container, you might see error messages like the following:
```
mkdir: cannot create directory '/lib/modules/3.10.0-693.el7.centos.test.x86_64/kernel/extra': Read-only file system
cp: cannot create regular file '/lib/modules/3.10.0-693.el7.centos.test.x86_64/kernel/extra/falco-probe.ko.xz': No such file or directory
```

These error messages are innocuous, but if you would like to remove them you can change the /host/lib/modules mount to read-write, by doing below change in `k8s-with-rbac/falco
daemonset-configmap.yaml`:

```
             - mountPath: /host/lib/modules
               name: lib-modules
-              readOnly: true
+              #readOnly: true
```

However, note that this will result in the `falco-probe.ko.xz` file being saved to `/lib/modules` on the host, even after the falco container is removed.


## Verifying the installation

In order to test that Falco is working correctly, you can launch a shell in a Pod. You should see a message in your Slack channel (if configured), or in the logs of the Falco pod.

```
k8s-using-daemonset$ kubectl get pods
NAME          READY     STATUS    RESTARTS   AGE
falco-74htl   1/1       Running   0          13h
falco-fqz2m   1/1       Running   0          13h
falco-sgjfx   1/1       Running   0          13h
k8s-using-daemonset$ kubectl exec -it falco-74htl bash
root@falco-74htl:/# exit
k8s-using-daemonset$ kubectl logs falco-74htl
{"output":"17:48:58.590038385: Notice A shell was spawned in a container with an attached terminal (user=root k8s.pod=falco-74htl container=a98c2aa8e670 shell=bash parent=<NA> cmdline=bash  terminal=34816)","priority":"Notice","rule":"Terminal shell in container","time":"2017-12-20T17:48:58.590038385Z", "output_fields": {"container.id":"a98c2aa8e670","evt.time":1513792138590038385,"k8s.pod.name":"falco-74htl","proc.cmdline":"bash ","proc.name":"bash","proc.pname":null,"proc.tty":34816,"user.name":"root"}}
k8s-using-daemonset$
```

Alternatively, you can deploy the [Falco Event Generator](https://github.com/draios/falco/wiki/Generating-Sample-Events) deployement to have events automatically generated. Please note that this Deployment will generate a large number of events.

```
k8s-using-daemonset$ kubectl create -f falco-event-generator-deployment.yaml \
&& sleep 1 \
&& kubectl delete -f falco-event-generator-deployment.yaml
deployment "falco-event-generator-deployment" created
deployment "falco-event-generator-deployment" deleted
k8s-using-daemonset$
```
