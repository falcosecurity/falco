# Create Falco rule from Anchore policy result

This integration creates a rule for Falco based on Anchore policy result.
So that when we will try to run an image which has a ```stop``` final action result
in Anchore, Falco will alert us.

## Getting started

### Prerequisites

For running this integration you will need:

* Python 3.6
* pipenv
* An [anchore-engine](https://github.com/anchore/anchore-engine) running

### Configuration

This integration uses the [same environment variables that anchore-cli](https://github.com/anchore/anchore-cli#configuring-the-anchore-cli):

* ANCHORE_CLI_USER: The user used to connect to anchore-engine. By default is ```admin```
* ANCHORE_CLI_PASS: The password used to connect to anchore-engine.
* ANCHORE_CLI_URL: The url where anchore-engine listens. Make sure does not end with a slash. By default is ```http://localhost:8228/v1```
* ANCHORE_CLI_SSL_VERIFY: Flag for enabling if HTTP client verifies SSL. By default is ```true```

### Running

This is a Python program which generates a Falco rule based on anchore-engine
information:

```
pipenv run python main.py
```

And this will output something like:


```yaml
- macro: anchore_stop_policy_evaluation_containers
  condition: container.image.id in ("8626492fecd368469e92258dfcafe055f636cb9cbc321a5865a98a0a6c99b8dd", "e86d9bb526efa0b0401189d8df6e3856d0320a3d20045c87b4e49c8a8bdb22c1")

- rule: Run Anchore Containers with Stop Policy Evaluation
  desc: Detect containers which does not receive a positive Policy Evaluation from Anchore Engine.

  condition: evt.type=execve and proc.vpid=1 and container and anchore_stop_policy_evaluation_containers
  output: A stop policy evaluation container from anchore has started (%container.info image=%container.image)
  priority: INFO
  tags: [container]
```

You can save that output to ```/etc/falco/rules.d/anchore-integration-rules.yaml```
and Falco will start checking this rule.

As long as information in anchore-engine can change, it's a good idea to run this
integration **periodically** and keep the rule synchronized with anchore-engine
policy evaluation result.

## Tests

As long as there are contract tests with anchore-engine, it needs a working
anchore-engine and its environment variables.

```
pipenv install -d
pipenv run mamba --format=documentation
```

## Docker support

### Build the image

```
docker build -t sysdig/anchore-falco .
```

### Running the image

An image exists on DockerHub, its name is ```sysdig/anchore-falco```.

So you can run directly with Docker:

```
docker run --rm -e ANCHORE_CLI_USER=<user-for-custom-anchore-engine> \
                -e ANCHORE_CLI_PASS=<password-for-user-for-custom-anchore-engine> \
                -e ANCHORE_CLI_URL=http://<custom-anchore-engine-host>:8228/v1 \
                sysdig/anchore-falco
```

And this will output the Falco rule based on *custom-anchore-engine-host*.
