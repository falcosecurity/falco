package main

import (
	"os"
	"log"
	"fmt"
	"github.com/falcosecurity/falco/pkg/falcoloader"
)

// Default behavior: calculate kernel module and download from Falco hosted probe library
// ENV FALCO_PROBE_URL = URL to download probe.ko file
// ENV FALCO_PROBE_REPO = URL to download probe.ko, probe name derived from `uname -r`

func main() {
	falcoVersion := getEnv("FALCO_VERSION","0.17.0")
	falcoProbePath := getEnv("FALCO_PROBE_PATH","/")
	falcoProbeFile := getEnv("FALCO_PROBE_FILE","falco-probe.ko")
	falcoProbeFullpath := falcoProbePath + falcoProbeFile
	falcoProbeURL := getEnv("FALCO_PROBE_URL","")
	falcoProbeRepo := getEnv("FALCO_PROBE_REPO","https://s3.amazonaws.com/download.draios.com/stable/sysdig-probe-binaries/")
	falcoConfigHash, err := falcoloader.GetKernelConfigHash()
	if err != nil {
		log.Fatalf("Error getting Kernel Config Hash: %s", err) 
	}
	falcoKernelRelease, err := falcoloader.GetKernelRelease()
	if err != nil {
		log.Fatalf("Error getting Kernel Version: %s", err)
	}
	log.Printf("FALCO_VERSION: %s", falcoVersion)
	log.Printf("FALCO_PROBE_URL: %s", falcoProbeURL)
	log.Printf("FALCO_PROBE_REPO: %s", falcoProbeRepo)
	log.Printf("KERNEL_VERSION: %s", falcoKernelRelease)
	log.Printf("KERNEL_CONFIG_HASH: %s", falcoConfigHash)

	// if FALCO_PROBE_URL not set, build it
	if falcoProbeURL == "" {
		falcoProbeURL = fmt.Sprintf("%sfalco-probe-%s-x86_64-%s-%s.ko", falcoProbeRepo, falcoVersion, falcoKernelRelease, falcoConfigHash)
	}

	// fetch module
	err = falcoloader.FetchModule(falcoProbeURL, falcoProbeFullpath)
	if err != nil {
		log.Fatalf("Error fetching module: %s", err)
	}

	// load module
	// Need to implement removal of module, retry loop, and timeout
	err = falcoloader.LoadModule(falcoProbeFullpath)
	if err != nil {
		log.Fatalf("Error loading module: %s", err)
	}
}

func getEnv(key, def string) string {
	value, ok := os.LookupEnv(key)
	if ok {
		return value
	}
	return def
}
