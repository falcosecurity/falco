# Terraform manifests for Kubernetes Response Engine running on AWS

In this directory are the Terraform manifests for creating required infrasturcture
for the Kubernetes Response Engine running with AWS technology: SNS for messaging
and Lambda for executing the playbooks.

## Deploy

For creating the resources, just run default Makefile target:

```
make
```

This will ask for an IAM user which creates the bridge between EKS rbac and AWS IAM.

## Clean

You can clean IAM roles and SNS topics with:

```
make clean
```
