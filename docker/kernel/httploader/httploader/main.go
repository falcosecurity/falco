package main

import "os"
import "log"
import "fmt"
import "./falcoloader"

// Default behavior: calculate kernel module and download from Falco hosted probe library
// ENV FALCO_PROBE_URL = URL to download probe.ko file
// ENV FALCO_PROBE_REPO = URL to download probe.ko, probe name derived from `uname -r`

func main() {
	falco_version := getEnv("FALCO_VERSION","0.17.0")
	falco_probe_path := getEnv("FALCO_PROBE_PATH","/")
	falco_probe_file := getEnv("FALCO_PROBE_FILE","falco-probe.ko")
	falco_probe_fullpath := falco_probe_path + falco_probe_file
	falco_probe_url := getEnv("FALCO_PROBE_URL","")
	falco_probe_repo := getEnv("FALCO_PROBE_REPO","https://s3.amazonaws.com/download.draios.com/stable/sysdig-probe-binaries/")
	falco_config_hash := falcoloader.GetKernelConfigHash()
	falco_kernel_version := falcoloader.GetKernelVersion()

	log.Printf("FALCO_VERSION: %s", falco_version)
	log.Printf("FALCO_PROBE_URL: %s", falco_probe_url)
	log.Printf("FALCO_PROBE_REPO: %s", falco_probe_repo)
	log.Printf("KERNEL_VERSION: %s", falco_kernel_version)
	log.Printf("KERNEL_CONFIG_HASH: %s", falco_config_hash)

	// if FALCO_PROBE_URL not set, build it
	if falco_probe_url == "" {
		falco_probe_url = fmt.Sprintf("%sfalco-probe-%s-x86_64-%s-%s.ko", falco_probe_repo, falco_version, falco_kernel_version, falco_config_hash)
	}

	// fetch module
	if err := falcoloader.FetchModule(falco_probe_url, falco_probe_fullpath); err != nil {
		panic(err)
	}

	// load module
	if err := falcoloader.LoadModule(falco_probe_fullpath); err != nil {
		panic(err)
	}
}

func getEnv(key, def string) string {
	value, isSet := os.LookupEnv(key)
	if (isSet) {
		return value
	}
	return def
}
