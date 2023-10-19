#generate helm documentation
DOCS_IMAGE_VERSION="v1.11.0"

#Here we use the "latest" tag since our CI uses the same(https://github.com/falcosecurity/charts/blob/2f04bccb5cacbbf3ecc2d2659304b74f865f41dd/.circleci/config.yml#L16).
LINT_IMAGE_VERSION="v3.8.0"

docs:
	docker run \
	--rm \
	--workdir=/helm-docs \
	--volume "$$(pwd):/helm-docs" \
	-u $$(id -u) \
	jnorwood/helm-docs:$(DOCS_IMAGE_VERSION) \
	helm-docs -t ./README.gotmpl -o ./generated/helm-values.md

lint: helm-repo-update
	docker run \
	-it \
	--workdir=/data \
	--volume $$(pwd)/..:/data \
	quay.io/helmpack/chart-testing:$(LINT_IMAGE_VERSION) \
	ct lint --config ./tests/ct.yaml --charts ./falco --chart-dirs .

helm-repo-update:
	helm repo update
