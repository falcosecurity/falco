# Falco regression tests

This folder contains the Regression tests suite for Falco.

You can find instructions on how to run this test suite on the Falco website [here](https://falco.org/docs/source/#run-regression-tests).

## Test suites

- [falco_tests](./falco_tests.yaml)
- [falco_traces](./falco_traces.yaml)
- [falco_tests_package](./falco_tests_package.yaml)
- [falco_k8s_audit_tests](./falco_k8s_audit_tests.yaml)
- [falco_tests_psp](./falco_tests_psp.yaml)

## Running locally

Using `virtualenv` the steps to locally run a specific test suite are the following ones (from this directory):

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

To obtain the path of all the available variants, execute:

```console
avocado variants --mux-yaml falco_test.yaml
```