# Falco regression tests

This folder contains the Regression tests suite for Falco.

You can find instructions on how to run this test suite on the Falco website [here](https://falco.org/docs/getting-started/source/#run-regression-tests).

## Test suites

- [falco_tests](./falco_tests.yaml)
- [falco_traces](./falco_traces.yaml.in)
- [falco_tests_package](./falco_tests_package.yaml)
- [falco_k8s_audit_tests](./falco_k8s_audit_tests.yaml)
- [falco_tests_psp](./falco_tests_psp.yaml)

## Running locally

This step assumes you already built Falco.

Note that the tests are intended to be run against a [release build](https://falco.org/docs/getting-started/source/#specify-the-build-type) of Falco, at the moment.

Also, it assumes you prepared [falco_traces](#falco_traces) (see the section below) and you already run the following command from the build directory:

```console
make test-trace-files
```

It prepares the fixtures (`json` and `scap` files) needed by the integration tests.

Using `virtualenv` the steps to locally run a specific test suite are the following ones (**from this directory**):

```console
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
BUILD_DIR="../build" avocado run --mux-yaml falco_tests.yaml --job-results-dir /tmp/job-results -- falco_test.py
deactivate
```

The name of the specific test suite to run is `falco_tests.yaml` in this case. Change it to run others test suites.

In case you want to only execute a specific test case, use the `--mux-filter-only` parameter as follows:

```console
BUILD_DIR="../build" avocado run --mux-yaml falco_tests.yaml --job-results-dir /tmp/job-results --mux-filter-only /run/trace_files/program_output -- falco_test.py
```

To obtain the path of all the available variants for a given test suite, execute:

```console
avocado variants --mux-yaml falco_tests.yaml
```

### falco_traces

The `falco_traces.yaml` test suite gets generated through the `falco_traces.yaml.in` file and some fixtures (`scap` files) downloaded from the web at execution time.

1. Ensure you have `unzip` and `xargs` utilities
2. Prepare the test suite with the following command:

    ```console
    bash run_regression_tests.sh -p -v
    ```

### falco_tests_package

The `falco_tests_package.yaml` test suite requires some additional setup steps to be succesfully run on your local machine.

In particular, it requires some runners (ie., docker images) to be already built and present into your local machine.

1. Ensure you have `docker` up and running
2. Ensure you build Falco (with bundled deps)

    The recommended way of doing it by running the `falcosecurity/falco-builder` docker image from the project root:

    ```console
    docker run -v $PWD/..:/source -v $PWD/mybuild:/build falcosecurity/falco-builder cmake
    docker run -v $PWD/..:/source -v $PWD/mybuild:/build falcosecurity/falco-builder falco
    ```

3. Ensure you build the Falco packages from the Falco above:

    ```console
    docker run -v $PWD/..:/source -v $PWD/mybuild:/build falcosecurity/falco-builder package
    ```

4. Ensure you build the runners:

    ```console
    FALCO_VERSION=$(./mybuild/release/userspace/falco/falco --version  | head -n 1 | cut -d' ' -f3 | tr -d '\r')
    mkdir -p /tmp/runners-rootfs
    cp -R ./test/rules /tmp/runners-rootfs
    cp -R ./test/trace_files /tmp/runners-rootfs
    cp ./mybuild/release/falco-${FALCO_VERSION}-x86_64.{deb,rpm,tar.gz} /tmp/runners-rootfs
    docker build -f docker/tester/root/runners/deb.Dockerfile --build-arg FALCO_VERSION=${FALCO_VERSION} -t falcosecurity/falco:test-deb /tmp/runners-rootfs
    docker build -f docker/tester/root/runners/rpm.Dockerfile --build-arg FALCO_VERSION=${FALCO_VERSION} -t falcosecurity/falco:test-rpm /tmp/runners-rootfs
    docker build -f docker/tester/root/runners/tar.gz.Dockerfile --build-arg FALCO_VERSION=${FALCO_VERSION} -t falcosecurity/falco:test-tar.gz /tmp/runners-rootfs
    ```

5. Run the `falco_tests_package.yaml` test suite from the `test` directory

    ```console
    cd test
    BUILD_DIR="../mybuild" avocado run --mux-yaml falco_tests_package.yaml --job-results-dir /tmp/job-results -- falco_test.py
    ```

### Execute all the test suites

In case you want to run all the test suites at once, you can directly use the `run_regression_tests.sh` runner script.

```console
cd test
./run_regression_tests.sh -v
```

Just make sure you followed all the previous setup steps.
