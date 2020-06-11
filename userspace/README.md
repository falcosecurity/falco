# Userspace

Here is where the main Falco engine lives.

There are two libraries here that are roughly seperated in the following way.are

### falco

This is the beloved `main()` function of the Falco program, as well as the logic for various falco outputs.

An output is just a way of delivering a Falco alert, the most simple output is the Falco stdout log.

### engine

This is the processing engine that connect the inbound stream of systemcalls to the rules engine.

This is the main powerhouse behind Falco, and does the assertion at runtime that compares system call events to rules.are


### CMake

If you are adding new files to either library you must define the `.cpp` file in the associated CMakeLists.txt file such that the linker will know where to find your new file.