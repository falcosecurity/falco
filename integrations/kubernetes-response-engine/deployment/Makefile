deploy:
	kubectl apply -f nats/
	kubectl create configmap falco-config --from-file=falco-config/ || true
	kubectl apply -f falco/
	kubectl apply -f kubeless/
	kubectl apply -f network-policy.yaml

clean:
	kubectl delete -f kubeless/
	kubectl delete configmap falco-config
	kubectl delete -f falco/
	kubectl delete -f nats/
	kubectl delete -f network-policy.yaml
