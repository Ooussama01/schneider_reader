package main

import (
	"bytes"
	//	"crypto/rand"
	//	"crypto/rsa"
	"crypto/tls"
	//	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	// "github.com/google/uuid"
	// "github.com/jacobsa/go-serial/serial"
)

const (
	mountPoint     = "/media/usboperation"
	privateKeyPath = "/home/root/.ssh/osm_id_rsa"
	publicKeyPath  = "/media/usboperation/auth/osm_id_rsa.pub"
	initJSONPath   = "/media/usboperation/conf/init.json"
	targetDir      = "/opt/plcnext/appshome/data/60002172000551/volumes/node-red/scripts/"
	outputFiles    = "/opt/plcnext/appshome/data/60002172000551/volumes/node-red/csv_files/"
	progressURL    = "https://172.16.85.25:51880/progress"

	// new for OPC UA client auth
	opcuaCertOnUSB = "/media/usboperation/certs/certificate.pem"
	opcuaKeyOnUSB  = "/media/usboperation/private/private_key.pem"
	opcuaCertDest  = "/etc/opcua/certificate.pem"
	opcuaKeyDest   = "/etc/opcua/private_key.pem"
)

func detectUSBDevice(label string) (string, error) {
	cmd := exec.Command("lsblk", "-r", "-o", "NAME,LABEL")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("lsblk failed: %w", err)
	}

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		if strings.Contains(line, label) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				device := fields[0]
				return "/dev/" + device, nil
			}
		}
	}
	return "", fmt.Errorf("device with label %s not found", label)
}

func sendProgressUpdate(value int, message, color string) {
	data := map[string]interface{}{
		"value":   value,
		"message": message,
		"color":   color,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	req, err := http.NewRequest("POST", progressURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()
}

func mountUSB(device, mountPoint string) error {
	if err := exec.Command("mkdir", "-p", mountPoint).Run(); err != nil {
		return err
	}
	return exec.Command("mount", device, mountPoint).Run()
}

func unmountUSB(mountPoint string) {
	_ = exec.Command("umount", mountPoint).Run()
}

func copyFiles() error {
	files, err := ioutil.ReadDir(outputFiles)
	if err != nil {
		return err
	}

	totalFiles := len(files)
	if totalFiles == 0 {
		return fmt.Errorf("no CSV files to copy")
	}

	sendProgressUpdate(0, "File transfer will start...", "blue")
	time.Sleep(1 * time.Second)

	copiedFiles := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(outputFiles, file.Name())
		baseName := file.Name()
		dateSuffix := time.Now().Format("20060102_150405")

		var newFileName string
		if filepath.Ext(filePath) == ".csv" {
			newFileName = fmt.Sprintf("%s_%s.csv", baseName[:len(baseName)-4], dateSuffix)
		} else {
			newFileName = fmt.Sprintf("%s_%s.txt", baseName, dateSuffix)
		}

		newFilePath := filepath.Join(mountPoint, newFileName)
		err := copyFile(filePath, newFilePath)
		if err != nil {
			return err
		}

		copiedFiles++
		percentage := (copiedFiles * 100) / totalFiles
		sendProgressUpdate(percentage, "Please wait!", "blue")
		time.Sleep(200 * time.Millisecond)
	}

	return nil
}

func copyFile(src, dst string) error {
	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, input, 0644)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	// Detect USB insertion (this is a placeholder)
	device, err := detectUSBDevice("OPERATION")
	if err != nil {
		log.Fatalf("Failed to detect USB device: %v", err)
	}

	sendProgressUpdate(0, "Validating your USB...", "grey")
	time.Sleep(1 * time.Second)

	log.Println(device)

	mountPoint := "/media/usboperation"
	err = mountUSB(device, mountPoint)
	if err != nil {
		sendProgressUpdate(0, "Failed to mount USB.", "red")
		log.Fatalf("Mount failed: %v", err)
	}

	defer unmountUSB(mountPoint)

	publicKey, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		sendProgressUpdate(0, "Public key not found.", "red")
		log.Fatalf("Public key not found: %v", err)
	}

	// Generate public key from the private key
	cmd := exec.Command("ssh-keygen", "-y", "-f", privateKeyPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		sendProgressUpdate(0, "Failed to generate public key.", "red")
		log.Fatalf("ssh-keygen failed: %v", err)
	}
	generatedPublicKey := strings.TrimSpace(out.String())
	usbPublicKey := strings.TrimSpace(string(publicKey))

	if generatedPublicKey == usbPublicKey {
		sendProgressUpdate(0, "USB is Authenticated...", "green")
		time.Sleep(1 * time.Second)

		// 1. Check if init.json exists and copy
		initJson := filepath.Join(mountPoint, "conf", "init.json")
		if _, err := os.Stat(initJson); err == nil {
			err = copyFile(initJson, filepath.Join(targetDir, "init.json"))
			if err != nil {
				log.Printf("Failed to copy init.json: %v", err)
			}
		} else {
			log.Println("init.json not found.")
		}

		// 2. Copy OPC UA client certificate if present
		if _, err := os.Stat(opcuaCertOnUSB); err == nil {
			err = copyFile(opcuaCertOnUSB, opcuaCertDest)
			if err != nil {
				log.Printf("Failed to copy OPC UA certificate: %v", err)
			} else {
				log.Println("OPC UA certificate copied successfully.")
			}
		} else {
			log.Println("OPC UA certificate not found on USB.")
		}

		// 3. Copy OPC UA private key if present
		if _, err := os.Stat(opcuaKeyOnUSB); err == nil {
			err = copyFile(opcuaKeyOnUSB, opcuaKeyDest)
			if err != nil {
				log.Printf("Failed to copy OPC UA private key: %v", err)
			} else {
				log.Println("OPC UA private key copied successfully.")
			}
		} else {
			log.Println("OPC UA private key not found on USB.")
		}

		// Restart the client to apply new certs
		cmd := exec.Command("service", "opcuaclient", "restart")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to restart OPC UA client: %v", err)
		} else {
			log.Println("OPC UA client restarted to load new cert/key.")
		}

		// 4. Copy CSV files
		err = copyFiles()
		if err != nil {
			sendProgressUpdate(0, "No CSV files to copy.", "red")
			log.Fatalf("File copy failed: %v", err)
		}

		// 5. Unmount USB
		unmountUSB(mountPoint)

		// 6. Final progress message
		sendProgressUpdate(100, "Transfer is done!", "green")

		// 7. Loop until USB removed
		for {
			time.Sleep(100 * time.Millisecond)
			_, err := detectUSBDevice("OPERATION")
			if err != nil {
				msg := fmt.Sprintf("Last transfer: %s", time.Now().Format("2006-01-02 15:04"))
				sendProgressUpdate(0, msg, "grey")
				break
			}
		}
	} else {

		sendProgressUpdate(0, "USB cannot be authenticated. Check USB...", "red")
		log.Fatalf("USB cannot be authenticated.")
	}
}

