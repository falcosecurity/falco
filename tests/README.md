# Falco unit tests

This folder contains the unit-tests suite for Falco.
The framework we use for unit-tests is [Catch2](https://github.com/catchorg/Catch2), while the one we use for mocking is [FakeIt](https://github.com/eranpeer/FakeIt).


## How to write tests

When you want to test a new file or test a non tested file, remember four steps:

- The folder structure here is the same as the one in the `userspace` folder, so `userspace/engine` becomes `tests/engine`.
- We call test files with this format `test_<original-file-name>.cpp`
- Update the `CMakeLists.txt` file to include your file in `FALCO_TESTS_SOURCES` and change the `FALCO_TESTED_LIBRARIES` accordingly. You might also need to add dependencies, in that case, look at `target_link_libraries` and `target_include_directories`
- If you are unsure on how to write tests, refer to our existing tests in this folder and to the [Catch2](https://github.com/catchorg/Catch2/tree/master/docs) documentation.

## How to execute tests

The suite can be configured with `cmake` and run with `make`.


In the root folder of Falco, after creating the build directory:

```bash
cd falco
mkdir build
cd build
```

You can prepare the tests with:

```
cmake ..
```

Optionally, you can customize the test suite by passing custom arguments like the examples below:

**filter all tests containing the word ctor**

```bash
cmake -DFALCO_TESTS_ARGUMENTS:STRING="-R ctor" ..
```

**verbose execution**

```bash
cmake -DFALCO_TESTS_ARGUMENTS:STRING="-V" ..
```


To see a list of all the custom arguments you may pass, execute `ctest --help` in your terminal.


Once you are ready, you can run your configuration with:

```bash
make tests
```
