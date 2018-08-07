deploy:
	kubectl apply -f nats/
	kubectl apply -f kubeless/
	kubectl apply -f network-policy.yaml

clean:
	kubectl delete -f kubeless/
	kubectl delete -f nats/
	kubectl delete -f network-policy.yaml
