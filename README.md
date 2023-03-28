### Running the binary

* Open a root shell
* Set the environment variable `COLLECTOR_URL`
```
export COLLECTOR_URL=http://44.201.76.235:2801/
```
* Load the kernel module
```
insmod ./build/driver/falco.ko
```
* Run the falco binary 
```
./build/userspace/falco/falco
```
