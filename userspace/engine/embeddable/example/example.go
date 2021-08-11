package main

//#cgo CFLAGS: -I../
//#cgo LDFLAGS: -L/home/mstemm/work/falco-build/userspace/engine/embeddable -lfalco_engine_embeddable -Wl,-rpath=/home/mstemm/work/falco-build/userspace/engine/embeddable
/*
#include "stdio.h"
#include "falco_engine_embeddable.h"

int open_engine(void **engine, void *rules_content)
{
   int32_t rc;
   *engine = falco_engine_embed_init(&rc);

   if (rc != 0)
   {
   return rc;
   }

   char *errstr;
   rc = falco_engine_embed_load_rules_content(*engine, (const char *) rules_content, &errstr);

   if (rc != 0)
   {
   fprintf(stderr, "%s", errstr);
   return rc;
   }

   rc = falco_engine_embed_open(*engine, &errstr);

   if (rc != 0)
   {
   fprintf(stderr, "%s", errstr);
   return rc;
   }

   return rc;
}

int next_result(void *engine, char **output)
{

   int32_t rc;
   falco_engine_embed_result *res;
   char *errstr;

   rc = falco_engine_embed_next_result(engine, &res, &errstr);

   if (rc != 0)
   {
   fprintf(stderr, "NEXT ERROR %s", errstr);
   return rc;
   }

   *output = res->output_str;
   return rc;

}

*/
import "C"

import (
	"fmt"
	"io/ioutil"
	"os"
	"unsafe"
)

func doMain(rules_filename string) int {

	rules_content, err := ioutil.ReadFile(rules_filename)
	if err != nil {
		fmt.Printf("Could not open rules file %s: %v", rules_filename, err)
		return 1
	}

	var handle unsafe.Pointer
	rc := C.open_engine(&handle, C.CBytes(rules_content))

	if rc != 0 {
		fmt.Printf("Could not open falco engine")
		return 1
	}

	for true {
		var output *C.char
		rc := C.next_result(handle, &output)
		if rc != 0 {
			fmt.Printf("Could not get next result")
			return 1
		}
		fmt.Printf("GOT RESULT %s\n", C.GoString(output))
	}

	return 0
}

func main() {
	os.Exit(doMain(os.Args[1]))
}


