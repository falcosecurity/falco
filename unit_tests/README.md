# Falco unit tests

## Intro

Under `unit_tests/engine` and `unit_tests/falco` directories, we have different test suites that could be a single file or an entire directory according to the number and the complexity of tests.

## Build and Run

```bash
cmake -DMINIMAL_BUILD=On -DBUILD_BPF=Off -DBUILD_DRIVER=Off -DBUILD_FALCO_UNIT_TESTS=On ..
make falco_unit_tests
sudo ./unit_tests/falco_unit_tests
```
