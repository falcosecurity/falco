all: create configure

create:
	terraform apply

configure:
	kubectl get -n kube-system configmap/aws-auth -o yaml | awk "/mapRoles: \|/{print;print \"$(shell terraform output patch_for_aws_auth)\";next}1" > aws-auth-patch.yml
	kubectl -n kube-system replace -f aws-auth-patch.yml

clean:
	terraform destroy
