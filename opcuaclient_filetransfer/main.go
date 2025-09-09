// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/*
*****************Program organization******************

* /usr/local/bin/opcua-client          ← binary
* /opt/opcuaclient/                   ← source (if you want it on device)
* /etc/opcua/                         ← certs + init.json
* /var/log/opcua-client/              ← logs
* /opt/plcnext/.../csv_files/         ← CSV outputs

***********************************************
 */
package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	//"sort"

	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/errors"
	uatest "github.com/gopcua/opcua/tests/python"
	"github.com/gopcua/opcua/ua"
)

var (
	endpoint = flag.String("endpoint", "opc.tcp://192.168.2.102:4840", "OPC UA Endpoint URL")
	certfile = flag.String("cert", "C:/Users/oouachani/Documents/opcuaclient_filetransfer/certs/uaexpert_local.pem", "Path to certificate file")
	keyfile  = flag.String("key", "C:/Users/oouachani/Documents/opcuaclient_filetransfer/certs/private_key_local.pem", "Path to PEM Private Key file")

	//certfile = flag.String("cert", "./certs/certificate.pem", "Path to certificate file")
	//keyfile  = flag.String("key", "./certs/private_key.pem", "Path to PEM Private Key file")
	//csvfile  = flag.String("csvNames", "tagsvalues", "Name of the analog and digital files")
	gencert  = flag.Bool("gen-cert", false, "Generate a new certificate")
	policy   = flag.String("sec-policy", "auto", "Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256")
	mode     = flag.String("sec-mode", "auto", "Security Mode: one of None, Sign, SignAndEncrypt")
	auth     = flag.String("auth-mode", "anonymous", "Authentication Mode: one of Anonymous, UserName, Certificate")
	appuri   = flag.String("app-uri", "urn:gopcua:client", "Application URI")
	list     = flag.Bool("list", false, "List the policies supported by the endpoint and exit")
	username = flag.String("user", "", "Username to use in auth-mode UserName; will prompt for input if omitted")
	password = flag.String("pass", "", "Password to use in auth-mode UserName; will prompt for input if omitted")
)

/*****CSVLogger handles CSV file rotation and writing******/

type CSVLogger struct {
	dir     string
	bucket  string
	file    *os.File
	writer  *csv.Writer
	curRef  string
	curWeek int
	curYear int
	headers []string
}

func main() {
	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()
	log.SetFlags(0)

	log.SetOutput(&lumberjack.Logger{
		//Filename:   "/opt/plcnext/appshome/data/60002172000551/volumes/node-red/csv_files/opcua_client.log", // log file path
		Filename:   "opcua_client.log", // log file path
		MaxSize:    5,                  // megabytes before rotation
		MaxBackups: 3,                  // number of old files to keep
		MaxAge:     28,                 // days to retain old logs
		Compress:   false,              // compress old files
	})

	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // add timestamp and file info

	/* for {
		if err := runClientLoop(); err != nil {
			log.Printf("Client loop exited with error: %v", err)
		}
		log.Println("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}*/

	// One-shot run
	if err := runClientLoop(); err != nil {
		log.Fatalf("Client run failed: %v", err)
	}
}

func runClientLoop() error {
	/*ctx := context.Background()

	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)
	if err != nil {
		return fmt.Errorf("failed to get endpoints: %w", err)
	}

	if *list {
		printEndpointOptions(endpoints)
		return nil
	}

	opts := clientOptsFromFlags(endpoints)
	c, err := opcua.NewClient(*endpoint, opts...)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}
	if err := c.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer c.Close(ctx)

	log.Println("Connected to OPC UA server") */

	ctx := context.Background()

	c, err := opcua.NewClient(*endpoint, opcua.SecurityMode(ua.MessageSecurityModeNone))
	if err != nil {
		log.Fatal(err)
	}
	if err := c.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	defer c.Close(ctx)
	log.Println("Connected to OPC UA server")

	// Call our pertu file copy
	if err := CopyAllPertuFiles(c, "./pertu_files", ctx); err != nil {
		return fmt.Errorf("failed to copy pertu files: %w", err)
	}

	log.Println("Completed copying pertu files")

	return nil
}

// CopyAllPertuFiles downloads all pertu files from the OPC UA server directory
// and saves them in a local directory.
func CopyAllPertuFiles(c *opcua.Client, localDir string, ctx context.Context) error {
	// 1. Get directory node
	dirNode := c.Node(ua.NewStringNodeID(7, "TestFolder|/opt/plcnext/transfer"))

	// 2. Get children (pertu files)
	children, err := dirNode.Children(ctx, 0, ua.NodeClassObject|ua.NodeClassVariable)
	if err != nil {
		return fmt.Errorf("failed to get children: %w", err)
	}
	if len(children) == 0 {
		return fmt.Errorf("no pertu files found")
	}

	for _, fileNode := range children {
		// --- Read Value attribute (pas toujours présent, on ne bloque pas)
		valResp, err := c.Read(ctx, &ua.ReadRequest{
			NodesToRead: []*ua.ReadValueID{{
				NodeID:      fileNode.ID,
				AttributeID: ua.AttributeIDValue,
			}},
			TimestampsToReturn: ua.TimestampsToReturnBoth,
		})

		fmt.Printf("Found file node %v\n", fileNode.ID)

		var timestamp time.Time
		if err != nil || valResp == nil || len(valResp.Results) == 0 || valResp.Results[0].Status != ua.StatusOK {
			fmt.Println("failed to read value:", err)
			timestamp = time.Now()
		} else {
			timestamp = valResp.Results[0].SourceTimestamp
			if timestamp.IsZero() {
				timestamp = valResp.Results[0].ServerTimestamp
			}
		}
		fmt.Printf("Timestamp: %v\n", timestamp)

		// --- Read BrowseName
		nameResp, err := c.Read(ctx, &ua.ReadRequest{
			NodesToRead: []*ua.ReadValueID{{
				NodeID:      fileNode.ID,
				AttributeID: ua.AttributeIDBrowseName,
			}},
		})
		if err != nil || nameResp == nil || len(nameResp.Results) == 0 || nameResp.Results[0].Status != ua.StatusOK {
			fmt.Println("failed to read browse name:", err)
			continue
		}

		var fileName string
		if qn, ok := nameResp.Results[0].Value.Value().(ua.QualifiedName); ok {
			fileName = qn.Name
		} else {
			fileName = fmt.Sprintf("%v", nameResp.Results[0].Value.Value())
		}

		fmt.Printf("Node %v at %v (name=%s)\n", fileNode.ID, timestamp, fileName)

		// 3. Call GenerateFileForRead
		transferNodeID := ua.NewStringNodeID(7, "TestFolder|/opt/plcnext/transfer")
		callReq := &ua.CallMethodRequest{
			ObjectID: transferNodeID,
			MethodID: ua.NewStringNodeID(0, "GenerateFileForRead"),
			InputArguments: []*ua.Variant{
				ua.MustVariant(fileNode.ID),
			},
		}
		callResp, err := c.Call(ctx, callReq)
		if err != nil {
			fmt.Println("GenerateFileForRead RPC failed:", err)
			continue
		}
		if callResp == nil || len(callResp.OutputArguments) < 2 {
			fmt.Println("GenerateFileForRead: no output arguments")
			continue
		}
		if callResp.StatusCode != ua.StatusOK {
			fmt.Println("GenerateFileForRead returned status:", callResp.StatusCode)
		}
		/*
			handleNodeID, ok1 := callResp.OutputArguments[0].Value().(*ua.NodeID)
			handle, ok2 := callResp.OutputArguments[1].Value().(uint32)
			if !ok1 || !ok2 {
				fmt.Println("unexpected types in GenerateFileForRead response")
				continue
			}

			fmt.Printf("GenerateFileForRead OK for %s → handleNodeID=%v handle=%v\n", fileName, handleNodeID, handle)

			/*
				// 4. Local file path
				localPath := fmt.Sprintf("%s/%s_%s.dat", localDir, fileName, timestamp.Format("20060102_150405"))
				f, err := os.Create(localPath)
				if err != nil {
					fmt.Println("failed to create local file:", err)
					continue
				}

				// 5. Read in chunks...
				// 6. Close file on server...
		*/
	}
	return nil
}

func clientOptsFromFlags(endpoints []*ua.EndpointDescription) []opcua.Option {
	opts := []opcua.Option{}

	// ApplicationURI is automatically read from the cert so is not required if a cert if provided
	if *certfile == "" && !*gencert {
		opts = append(opts, opcua.ApplicationURI(*appuri))
	}

	var cert []byte
	var privateKey *rsa.PrivateKey
	if *gencert || (*certfile != "" && *keyfile != "") {
		if *gencert {
			// Create directories only if they don't exist
			certDir := filepath.Dir(*certfile)
			keyDir := filepath.Dir(*keyfile)

			if _, err := os.Stat(certDir); os.IsNotExist(err) {
				if err := os.MkdirAll(certDir, 0755); err != nil {
					log.Fatalf("failed to create cert directory: %v", err)
				}
			}

			if _, err := os.Stat(keyDir); os.IsNotExist(err) {
				if err := os.MkdirAll(keyDir, 0755); err != nil {
					log.Fatalf("failed to create key directory: %v", err)
				}
			}

			certPEM, keyPEM, err := uatest.GenerateCert(*appuri, 2048, 24*time.Hour)
			if err != nil {
				log.Fatalf("failed to generate cert: %v", err)
			}

			if err := os.WriteFile(*certfile, certPEM, 0644); err != nil {
				log.Fatalf("failed to write %s: %v", *certfile, err)
			}
			if err := os.WriteFile(*keyfile, keyPEM, 0644); err != nil {
				log.Fatalf("failed to write %s: %v", *keyfile, err)
			}

			block, _ := pem.Decode(certPEM)
			if block == nil || block.Type != "CERTIFICATE" {
				log.Fatalf("failed to decode PEM certificate, got block type: %v", block.Type)
			}

			outputPath := "own/certs/cert.der"
			if err := os.WriteFile(outputPath, block.Bytes, 0644); err != nil {
				log.Fatalf("failed to write DER certificate to %s: %v", outputPath, err)
			}
		}

		debug.Printf("Loading cert/key from %s , %s", *certfile, *keyfile)
		c, err := tls.LoadX509KeyPair(*certfile, *keyfile)
		if err != nil {
			log.Printf("Failed to load certificate: %s", err)
		} else {
			pk, ok := c.PrivateKey.(*rsa.PrivateKey)
			if !ok {
				log.Fatalf("Invalid private key")
			}
			cert = c.Certificate[0]
			privateKey = pk
			opts = append(opts, opcua.PrivateKey(pk), opcua.Certificate(cert))
		}
	}

	var secPolicy string
	switch {
	case *policy == "auto":
		// set it later
	case strings.HasPrefix(*policy, ua.SecurityPolicyURIPrefix):
		secPolicy = *policy
		*policy = ""
	case *policy == "None" || *policy == "Basic128Rsa15" || *policy == "Basic256" || *policy == "Basic256Sha256" || *policy == "Aes128_Sha256_RsaOaep" || *policy == "Aes256_Sha256_RsaPss":
		secPolicy = ua.SecurityPolicyURIPrefix + *policy
		*policy = ""
	default:
		log.Fatalf("Invalid security policy: %s", *policy)
	}

	// Select the most appropriate authentication mode from server capabilities and user input
	authMode, authOptions := authFromFlags(cert, privateKey)
	opts = append(opts, authOptions...)

	var secMode ua.MessageSecurityMode
	switch strings.ToLower(*mode) {
	case "auto":
	case "none":
		secMode = ua.MessageSecurityModeNone
		*mode = ""
	case "sign":
		secMode = ua.MessageSecurityModeSign
		*mode = ""
	case "signandencrypt":
		secMode = ua.MessageSecurityModeSignAndEncrypt
		*mode = ""
	default:
		log.Fatalf("Invalid security mode: %s", *mode)
	}

	// Allow input of only one of sec-mode,sec-policy when choosing 'None'
	if secMode == ua.MessageSecurityModeNone || secPolicy == ua.SecurityPolicyURINone {
		secMode = ua.MessageSecurityModeNone
		secPolicy = ua.SecurityPolicyURINone
	}

	// Find the best endpoint based on our input and server recommendation (highest SecurityMode+SecurityLevel)
	var serverEndpoint *ua.EndpointDescription
	switch {
	case *mode == "auto" && *policy == "auto": // No user selection, choose best
		for _, e := range endpoints {
			if serverEndpoint == nil || (e.SecurityMode >= serverEndpoint.SecurityMode && e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	case *mode != "auto" && *policy == "auto": // User only cares about mode, select highest securitylevel with that mode
		for _, e := range endpoints {
			if e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	case *mode == "auto" && *policy != "auto": // User only cares about policy, select highest securitylevel with that policy
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}

	default: // User cares about both
		fmt.Println("secMode: ", secMode, "secPolicy:", secPolicy)
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	}

	if serverEndpoint == nil { // Didn't find an endpoint with matching policy and mode.
		log.Printf("unable to find suitable server endpoint with selected sec-policy and sec-mode")
		printEndpointOptions(endpoints)
		log.Fatalf("quitting")
	}

	secPolicy = serverEndpoint.SecurityPolicyURI
	secMode = serverEndpoint.SecurityMode

	// Check that the selected endpoint is a valid combo
	err := validateEndpointConfig(endpoints, secPolicy, secMode, authMode)
	if err != nil {
		log.Fatalf("error validating input: %s", err)
	}

	opts = append(opts, opcua.SecurityFromEndpoint(serverEndpoint, authMode))

	log.Printf("Using config:\nEndpoint: %s\nSecurity mode: %s, %s\nAuth mode : %s\n", serverEndpoint.EndpointURL, serverEndpoint.SecurityPolicyURI, serverEndpoint.SecurityMode, authMode)
	return opts
}

func authFromFlags(cert []byte, pk *rsa.PrivateKey) (ua.UserTokenType, []opcua.Option) {
	var err error

	var authMode ua.UserTokenType
	var authOptions []opcua.Option
	switch strings.ToLower(*auth) {
	case "anonymous":
		authMode = ua.UserTokenTypeAnonymous
		authOptions = append(authOptions, opcua.AuthAnonymous())

	case "username":
		authMode = ua.UserTokenTypeUserName

		if *username == "" {
			fmt.Print("Enter username: ")
			*username, err = bufio.NewReader(os.Stdin).ReadString('\n')
			*username = strings.TrimSuffix(*username, "\n")
			if err != nil {
				log.Fatalf("error reading username input: %s", err)
			}
		}

		passPrompt := true
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "pass" {
				passPrompt = false
			}
		})

		if passPrompt {
			fmt.Print("Enter password: ")
			passInput, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatalf("Error reading password: %s", err)
			}
			*password = string(passInput)
			fmt.Print("\n")
		}
		authOptions = append(authOptions, opcua.AuthUsername(*username, *password))

	case "certificate":
		authMode = ua.UserTokenTypeCertificate
		// Note: You should still use these two Config options to load the auth certificate and private key
		// separately from the secure channel configuration even if the same certificate is used for both purposes
		authOptions = append(authOptions, opcua.AuthCertificate(cert))
		authOptions = append(authOptions, opcua.AuthPrivateKey(pk))

	case "issuedtoken":
		// todo: this is unsupported, fail here or fail in the opcua package?
		authMode = ua.UserTokenTypeIssuedToken
		authOptions = append(authOptions, opcua.AuthIssuedToken([]byte(nil)))

	default:
		log.Printf("unknown auth-mode, defaulting to Anonymous")
		authMode = ua.UserTokenTypeAnonymous
		authOptions = append(authOptions, opcua.AuthAnonymous())

	}

	return authMode, authOptions
}

func validateEndpointConfig(endpoints []*ua.EndpointDescription, secPolicy string, secMode ua.MessageSecurityMode, authMode ua.UserTokenType) error {
	for _, e := range endpoints {
		if e.SecurityMode == secMode && e.SecurityPolicyURI == secPolicy {
			for _, t := range e.UserIdentityTokens {
				if t.TokenType == authMode {
					return nil
				}
			}
		}
	}

	err := errors.Errorf("server does not support an endpoint with security : %s , %s, %s", secPolicy, secMode, authMode)
	printEndpointOptions(endpoints)
	return err
}

func printEndpointOptions(endpoints []*ua.EndpointDescription) {
	log.Print("Valid options for the endpoint are:")
	log.Print("         sec-policy    |    sec-mode     |      auth-modes\n")
	log.Print("-----------------------|-----------------|---------------------------\n")
	for _, e := range endpoints {
		p := strings.TrimPrefix(e.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#")
		m := strings.TrimPrefix(e.SecurityMode.String(), "MessageSecurityMode")
		var tt []string
		for _, t := range e.UserIdentityTokens {
			tok := strings.TrimPrefix(t.TokenType.String(), "UserTokenType")

			// Just show one entry if a server has multiple varieties of one TokenType (eg. different algorithms)
			dup := false
			for _, v := range tt {
				if tok == v {
					dup = true
					break
				}
			}
			if !dup {
				tt = append(tt, tok)
			}
		}
		log.Printf("%22s | %-15s | (%s)", p, m, strings.Join(tt, ","))
	}
}
