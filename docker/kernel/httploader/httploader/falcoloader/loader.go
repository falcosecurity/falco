package falcoloader

import "io/ioutil"
import "io"
import "os"
import "crypto/md5"
import "encoding/hex"
import "strings"
import "net/http"
import "golang.org/x/sys/unix"
import "log"
import "unsafe"
import "compress/gzip"
import "bytes"

func GetKernelVersion() string {
	path := "/proc/version"

	file, err := ioutil.ReadFile(path)
	if err != nil {
		return "invaildVersion"
	}
	version_string := string(file)

	version_fields := strings.Split(version_string, " ")

	return version_fields[2]
}

func GetKernelConfigHash() string {
	var hash string
	kernelConfigPath := getKernelConfigPath()
	hash, _ = genKernelConfigHash(kernelConfigPath)

	return hash
}

func getKernelConfigPath() string {
	kernelConfigPath := ""

	version := GetKernelVersion()
	paths := []string{ 
		"/proc/config.gz", 
		"/boot/config-" + version, 
		"/host/boot/config-" + version, 
		"/usr/lib/ostree-boot/config-" + version,
		"/usr/lib/ostree-boot/config-" + version,
		"/lib/modules/" + version + "/config" }

	for i := range paths {
		_, err := os.Stat(paths[i])
		if err != nil {
			continue;
		}
		log.Print("Found kernel config: " + paths[i])
		return paths[i]
	}
	log.Fatal("No kernel config found")
	return kernelConfigPath
}

func genKernelConfigHash(path string) (string, error) { 
	var md5hash string
	var err error
	var buf bytes.Buffer
	
	if strings.HasSuffix(path, "gz") {
		log.Print("Kernel config " + path + " is gz compressed")
		tmpfile, err := os.Open(path)
		if err != nil {
			return md5hash, err
		}
		defer tmpfile.Close()

		file, err := gzip.NewReader(tmpfile)
		if err != nil {
			return md5hash, err
		}
		defer file.Close()
		io.Copy(&buf, file)
	} else {
		file, err := os.Open(path)
		if err != nil {
			return md5hash, err
		}
		defer file.Close()
		io.Copy(&buf,file)
	}
	
	hash := md5.New()
	if _, err := io.Copy(hash, &buf); err != nil {
		return md5hash, err
	}
	md5hash = hex.EncodeToString(hash.Sum(nil))
	log.Print("Hash calculated: " + md5hash)

	return md5hash, err

}

func FetchModule(url string, path string) error {
	log.Printf("Downloading kernel module from %s", url)
    resp, err := http.Get(url)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
	log.Printf("Recevied HTTP Status Code: %d", resp.StatusCode)
	if resp.StatusCode == 200 {
		out, err := os.Create(path)
		if err != nil {
			log.Fatalf("Error creating file: %s", path)
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			log.Fatalf("Unable to write file: %s", path)
			return err
		}
		log.Printf("Wrote kernel module: %s", path)
	} else {
		log.Fatal("Non-200 Status code received.")
	}
	return err
	
}

func LoadModule(path string) error {

	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening kernel module: %s", path)
		return err
	}

	log.Print("Opened probe: " + path)

	_p0, err := unix.BytePtrFromString("")

	if _, _, err := unix.Syscall(313, file.Fd(), uintptr(unsafe.Pointer(_p0)), 0); err != 0 {
		log.Fatalf("Error loading kernel module: %s. The module may already be loaded.", path)
		return err
	}
	
	return err
}
