// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

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
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	endpoint = flag.String("endpoint", "opc.tcp://127.0.0.1:48010", "OPC UA Endpoint URL")
	certfile = flag.String("cert", "C:/Users/oouachani/AppData/Roaming/unifiedautomation/uaexpert/PKI/own/certs/uaexpert_converted.pem", "Path to certificate file")
	keyfile  = flag.String("key", "C:/Users/oouachani/AppData/Roaming/unifiedautomation/uaexpert/PKI/own/private/uaexpert_key.pem", "Path to PEM Private Key file")
	//csvfile  = flag.String("csvNames", "tagsvalues", "Name of the analog and digital files")
	gencert  = flag.Bool("gen-cert", false, "Generate a new certificate")
	policy   = flag.String("sec-policy", "Aes256_Sha256_RsaPss", "Security Policy URL or one of None, Basic128Rsa15, Basic256, Basic256Sha256")
	mode     = flag.String("sec-mode", "SignAndEncrypt", "Security Mode: one of None, Sign, SignAndEncrypt")
	auth     = flag.String("auth-mode", "Certificate", "Authentication Mode: one of Anonymous, UserName, Certificate")
	appuri   = flag.String("app-uri", "urn:gopcua:client", "Application URI")
	list     = flag.Bool("list", false, "List the policies supported by the endpoint and exit")
	username = flag.String("user", "", "Username to use in auth-mode UserName; will prompt for input if omitted")
	password = flag.String("pass", "", "Password to use in auth-mode UserName; will prompt for input if omitted")
)

/*****CSVLogger handles CSV file rotation and writing******/
//bucket is
//dir is
//file refers to

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

func NewCSVLogger(dir, bucket string) *CSVLogger {
	return &CSVLogger{
		dir:    dir,
		bucket: bucket,
	}
}

func (l *CSVLogger) rotateIfNeeded(ref string, week, year int, headers []string) error {
	//only rotate if ref, week, or year changes
	if l.file == nil || l.curRef != ref || l.curWeek != week || l.curYear != year {
		if l.file != nil {
			l.writer.Flush()
			l.file.Close()
		}
		//Create a new file
		filename := fmt.Sprintf("%s_%s_Y%d__W%d.csv", ref, l.bucket, year, week)
		path := filepath.Join(l.dir, filename)

		// Make sure directory exists
		if err := os.MkdirAll(l.dir, 0755); err != nil {
			return fmt.Errorf("failed to create CSV dir: %w", err)
		}

		// Open in append mode if exists, create otherwise
		fileExists := false
		if _, err := os.Stat(path); err == nil {
			fileExists = true
		}

		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open CSV file: %w", err)
		}

		l.file = f
		l.writer = csv.NewWriter(f)
		l.curWeek = week
		l.curRef = ref
		l.curYear = year
		l.headers = headers

		// Write header only if file is new
		if !fileExists {
			if err := l.writer.Write(headers); err != nil {
				return fmt.Errorf("failed to write CSV header: %w", err)
			}
		}

		// Always flush after writing
		l.writer.Flush()
		if err := l.writer.Error(); err != nil {
			return fmt.Errorf("failed to flush CSV writer: %w", err)
		}

		return nil
	}
	return nil
}

func (l *CSVLogger) writeRow(values []string) error {
	if l.writer == nil {
		return fmt.Errorf("CSV writer not initialized")
	}
	if err := l.writer.Write(values); err != nil {
		return err
	}
	l.writer.Flush()
	return nil
}

func main() {
	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()
	log.SetFlags(0)

	// ====> Chemin LOG local Windows (fichier) + duplication console
	_ = os.MkdirAll("C:/Users/oouachani/Documents/opcua_logs", 0755)
	logFile := &lumberjack.Logger{
		Filename:   "C:/Users/oouachani/Documents/opcua_logs/opcua_client.log",
		MaxSize:    5,  // megabytes before rotation
		MaxBackups: 3,  // number of old files to keep
		MaxAge:     28, // days to retain old logs
		Compress:   false,
	}
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile) // add timestamp and file info

	for {
		if err := runClientLoop(); err != nil {
			log.Printf("Client loop exited with error: %v", err)
		}
		log.Println("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

func runClientLoop() error {
	ctx := context.Background()

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

	nodeIDs := []string{
		"ns=7;s=AirConditionerXml.Humidity",
	}

	req := &ua.ReadRequest{
		MaxAge: 2000,
		NodesToRead: func() []*ua.ReadValueID {
			list := make([]*ua.ReadValueID, len(nodeIDs))
			for i, id := range nodeIDs {
				list[i] = &ua.ReadValueID{NodeID: ua.MustParseNodeID(id)}
			}
			return list
		}(),
		TimestampsToReturn: ua.TimestampsToReturnBoth,
	}

	// ====> Chemin CSV local Windows
	csvDir := "C:/Users/oouachani/Documents/opcua_logs/csv"
	_ = os.MkdirAll(csvDir, 0755)
	logger := NewCSVLogger(csvDir, "ANALOG")
	reference := "VISOR"

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Logging every second...")

	for range ticker.C {
		resp, err := c.Read(ctx, req)
		if err != nil {
			log.Printf("read failed: %v", err) // log explicite avant retour
			return fmt.Errorf("read failed: %w", err)
		}

		now := time.Now()
		payload := extractTagValues(nodeIDs, resp.Results, now)

		// ====> Log en console + fichier des valeurs lues (diagnostic)
		log.Printf("%s %s %s %s",
			payload["_time"],
			payload["weekNumber"],
			payload["yearNumber"],
			payload["ns=7;s=AirConditionerXml.Humidity"],
		)

		week := atoi(payload["weekNumber"])
		year := atoi(payload["yearNumber"])

		fixedPrefix := []string{"_time", "weekNumber", "yearNumber"}
		tagNames := make([]string, 0)
		for k := range payload {
			if k != "_time" && k != "weekNumber" && k != "yearNumber" {
				tagNames = append(tagNames, k)
			}
		}
		sort.Strings(tagNames)
		headers := append(append([]string{}, fixedPrefix...), tagNames...)

		values := make([]string, len(headers))
		for i, h := range headers {
			values[i] = payload[h]
		}

		if err := logger.rotateIfNeeded(reference, week, year, headers); err != nil {
			log.Printf("Rotation failed: %v", err)
			continue
		}
		if err := logger.writeRow(values); err != nil {
			log.Printf("Write failed: %v", err)
		}
	}

	return nil
}

// Extract Tag Values by converting OPC UA Read results into a map for CSV
func extractTagValues(nodeIDs []string, results []*ua.DataValue, now time.Time) map[string]string {
	payload := make(map[string]string)

	//Add the time first
	payload["_time"] = now.Format(time.RFC3339)
	_, week := now.ISOWeek()
	payload["weekNumber"] = strconv.Itoa(week)
	payload["yearNumber"] = strconv.Itoa(now.Year())

	for i, id := range nodeIDs {
		if i >= len(results) {
			continue
		}
		switch v := results[i].Value.Value().(type) {
		case float32:
			payload[id] = fmt.Sprintf("%.2f", v)
		case float64:
			payload[id] = fmt.Sprintf("%.2f", v)
		default:
			payload[id] = fmt.Sprintf("%v", v)
		}
	}
	return payload
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

			outputPath := "/etc/opcua/certificate.der"
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

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
