package main

//#cgo CFLAGS: -I../
//#cgo LDFLAGS: -L/home/mstemm/work/falco-build/userspace/engine/embeddable -lfalco_engine_embeddable -Wl,-rpath=/home/mstemm/work/falco-build/userspace/engine/embeddable
/*
#include "falco_engine_embeddable.h"

int open_engine(void **engine)
{
   int32_t rc;
   *engine = falco_engine_embed_init(&rc);

   return rc;
}
*/
import "C"

import (
)

func doMain(path string, rules_file string) {
	var handle unsafe.Pointer
	rc := C.open_engine(&handle)

	if rc != 0 {
		fmt.Printf("Could not open falco engine")
		return 1
	}

	return 0
}

func main() {
	os.Exit(doMain(Args[1]))
}


