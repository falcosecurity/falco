deploy:
	kubectl apply -f nats/
	kubectl apply -f kubeless/
	kubectl apply -f ../cluster-role.yaml
	kubectl apply -f .

clean:
	kubectl delete -f kubeless/
	kubectl delete -f nats/
	kubectl delete -f .
	kubectl delete -f ../cluster-role.yaml
