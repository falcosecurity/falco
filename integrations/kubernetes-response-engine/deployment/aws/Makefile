deploy: rbac create configure

rbac:
	kubectl apply -f ../cluster-role.yaml
	kubectl apply -f cluster-role-binding.yaml

create:
	terraform apply -auto-approve

configure:
	kubectl get -n kube-system configmap/aws-auth -o yaml | awk "/mapRoles: \|/{print;print \"$(shell terraform output patch_for_aws_auth)\";next}1" > aws-auth-patch.yml
	kubectl -n kube-system replace -f aws-auth-patch.yml

clean:
	terraform destroy -force
	kubectl delete -f cluster-role-binding.yaml
	kubectl delete -f ../cluster-role.yaml
