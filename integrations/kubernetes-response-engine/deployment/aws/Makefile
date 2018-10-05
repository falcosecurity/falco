all: create configure

create:
	terraform apply

configure:
	terraform output kubeconfig > kubeconfig
	terraform output config_map_aws_auth > aws_auth.yaml
	kubectl --kubeconfig=kubeconfig apply -f aws_auth.yaml
