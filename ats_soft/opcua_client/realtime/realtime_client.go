// realtime_client.go
// CSV en temps réel avec 2 entrées (ANALOG + DIGIT) et 2 sorties séparées.
// REFERENCE lue dans opcua_client/config.json
// Connexion par défaut: 127.0.0.1 + None/None + Anonymous.

package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
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
	// === Defaults pour ton cas: 127.0.0.1 / None / None / Anonymous ===
	endpoint = flag.String("endpoint", "opc.tcp://127.0.0.1:48010", "OPC UA Endpoint URL")
	certfile = flag.String("cert", "C:/Users/oouachani/Downloads/certs(corridiona_new)/certs(corridiona_new)/uaexpert.pem", "Path to certificate file")
	keyfile  = flag.String("key", "C:/Users/oouachani/Downloads/certs(corridiona_new)/certs(corridiona_new)/uaexpert_key.pem", "Path to PEM Private Key file")
	gencert  = flag.Bool("gen-cert", false, "Generate a new certificate")

	policy = flag.String("sec-policy", "None", "Security Policy: None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss")
	mode   = flag.String("sec-mode", "None", "Security Mode: None, Sign, SignAndEncrypt")
	auth   = flag.String("auth-mode", "Anonymous", "Authentication: Anonymous, UserName, Certificate")

	appuri = flag.String("app-uri", "urn:gopcua:client", "Application URI")
	list   = flag.Bool("list", false, "List endpoint security options and exit")

	username = flag.String("user", "", "Username for auth-mode UserName")
	password = flag.String("pass", "", "Password for auth-mode UserName")

	// === Deux CSV d'entrée par défaut ===
	csvAnalogPath = flag.String("csv-analog", "C:/Users/oouachani/Downloads/nodeids_quoted_ANALOG.csv", "Analog NodeIDs CSV (col0=NodeId, col1=Alias optionnel)")
	csvDigitPath  = flag.String("csv-digit", "C:/Users/oouachani/Downloads/nodeids_quoted_DIGIT.csv", "Digital NodeIDs CSV (col0=NodeId, col1=Alias optionnel)")

	outDir     = flag.String("out", "C:/Users/oouachani/Documents/csv_files", "Output directory for CSV files")
	configPath = flag.String("config", "C:/Users/oouachani/Documents/ats_soft/opcua_client/config.json", "Path to config.json")
)

// --- Config JSON pour REFERENCE/TIMEZONE/overrides ---
type RTConfig struct {
	Reference     string `json:"REFERENCE,omitempty"`
	Timezone      string `json:"TIMEZONE,omitempty"`
	CSVAnalogPath string `json:"CSV_ANALOG_PATH,omitempty"`
	CSVDigitPath  string `json:"CSV_DIGIT_PATH,omitempty"`
	OutDir        string `json:"OUT_DIR,omitempty"`
	Retention     int    `json:"RETENTION,omitempty"`
}

// ===== CSV LOGGER =====

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
	return &CSVLogger{dir: dir, bucket: bucket}
}

func (l *CSVLogger) rotateIfNeeded(ref string, week, year int, headers []string) error {
	if l.file == nil || l.curRef != ref || l.curWeek != week || l.curYear != year {
		if l.file != nil {
			l.writer.Flush()
			_ = l.file.Close()
		}
		filename := fmt.Sprintf("%s_%s_Y%d_W%d.csv", ref, l.bucket, year, week)
		path := filepath.Join(l.dir, filename)

		if err := os.MkdirAll(l.dir, 0755); err != nil {
			return fmt.Errorf("failed to create CSV dir: %w", err)
		}

		existed := false
		if _, err := os.Stat(path); err == nil {
			existed = true
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
		if err != nil {
			return fmt.Errorf("open file: %w", err)
		}

		needRewriteHeader := !existed
		if existed {
			if _, err := f.Seek(0, 0); err == nil {
				r := csv.NewReader(f)
				r.Comma = ';'
				first, rerr := r.Read()
				if rerr != nil || !equalStringSlices(first, headers) {
					needRewriteHeader = true
				}
			} else {
				needRewriteHeader = true
			}
		}
		if needRewriteHeader {
			if err := f.Truncate(0); err != nil {
				_ = f.Close()
				return fmt.Errorf("truncate: %w", err)
			}
			if _, err := f.Seek(0, 0); err != nil {
				_ = f.Close()
				return fmt.Errorf("seek: %w", err)
			}
		}

		w := csv.NewWriter(f)
		w.Comma = ';'

		if needRewriteHeader {
			if err := w.Write(headers); err != nil {
				_ = f.Close()
				return fmt.Errorf("write header: %w", err)
			}
			w.Flush()
			if err := w.Error(); err != nil {
				_ = f.Close()
				return fmt.Errorf("flush header: %w", err)
			}
		}

		l.file = f
		l.writer = w
		l.curWeek = week
		l.curRef = ref
		l.curYear = year
		l.headers = headers
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

// ===== MAIN =====

func main() {
	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()

	// Log rotation file (peut être surchargé par RETENTION dans runClientLoop)
	log.SetOutput(&lumberjack.Logger{
		Filename:   "C:/Users/oouachani/Downloads/opcua_client.log",
		MaxSize:    5,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   false,
	})
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	for {
		if err := runClientLoop(); err != nil {
			log.Printf("Client loop exited with error: %v", err)
		}
		log.Println("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

// ===== UTILS =====

// CSV -> nodeIDs + displayNames (alias si present)
func readTagSpecsCSV(path string) ([]string, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open csv: %w", err)
	}
	defer f.Close()

	try := func(delim rune) ([][]string, error) {
		if _, err := f.Seek(0, 0); err != nil {
			return nil, fmt.Errorf("seek: %w", err)
		}
		r := csv.NewReader(f)
		r.Comma = delim
		r.FieldsPerRecord = -1
		r.TrimLeadingSpace = true
		return r.ReadAll()
	}

	rows, err := try(',')
	if err != nil {
		return nil, nil, fmt.Errorf("read with ',': %w", err)
	}
	hasSecond := false
	for _, rec := range rows {
		if len(rec) >= 2 && strings.TrimSpace(rec[1]) != "" {
			hasSecond = true
			break
		}
	}
	if !hasSecond {
		rows, err = try(';')
		if err != nil {
			return nil, nil, fmt.Errorf("read with ';': %w", err)
		}
	}

	trimAll := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimSuffix(s, "\r")
		s = strings.Trim(s, "\"\u201C\u201D")
		return s
	}

	var nodeIDs, displayNames []string
	for i, rec := range rows {
		if len(rec) == 0 {
			continue
		}
		id := rec[0]
		if i == 0 {
			id = strings.TrimPrefix(id, "\ufeff")
		}
		id = trimAll(id)
		if id == "" {
			continue
		}
		name := id
		if len(rec) > 1 {
			if alias := trimAll(rec[1]); alias != "" {
				name = alias
			}
		}
		nodeIDs = append(nodeIDs, id)
		displayNames = append(displayNames, name)
	}
	return nodeIDs, displayNames, nil
}

// Map résultat -> colonnes
func extractTagValuesIndexed(nodeIDs, displayNames []string, results []*ua.DataValue, now time.Time) map[string]string {
	out := map[string]string{
		"_time":      now.Format(time.RFC3339),
		"weekNumber": strconv.Itoa(func() int { _, w := now.ISOWeek(); return w }()),
		"yearNumber": strconv.Itoa(now.Year()),
	}
	n := len(nodeIDs)
	if len(results) < n {
		n = len(results)
	}
	for i := 0; i < n; i++ {
		name := displayNames[i]
		dv := results[i]
		if dv == nil || dv.Value == nil {
			out[name] = ""
			continue
		}
		switch v := dv.Value.Value().(type) {
		case float32:
			out[name] = fmt.Sprintf("%.2f", v)
		case float64:
			out[name] = fmt.Sprintf("%.2f", v)
		case bool:
			out[name] = strconv.FormatBool(v)
		case string:
			out[name] = v
		case time.Time:
			out[name] = v.Format(time.RFC3339)
		default:
			out[name] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

// Charger RT config
func loadRTConfig(path string) RTConfig {
	var cfg RTConfig
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("⚠️ Impossible de lire %s: %v (defaults)", path, err)
		return cfg
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Printf("⚠️ JSON invalide dans %s: %v (defaults)", path, err)
		return RTConfig{}
	}
	return cfg
}

// ===== LOOP =====

func runClientLoop() error {
	ctx := context.Background()

	// 1) Charger config JSON (REFERENCE / TIMEZONE / overrides CSV & OUT)
	cfg := loadRTConfig(*configPath)

	// Surcouches éventuelles depuis JSON
	if strings.TrimSpace(cfg.CSVAnalogPath) != "" {
		*csvAnalogPath = cfg.CSVAnalogPath
	}
	if strings.TrimSpace(cfg.CSVDigitPath) != "" {
		*csvDigitPath = cfg.CSVDigitPath
	}
	if strings.TrimSpace(cfg.OutDir) != "" {
		*outDir = cfg.OutDir
	}

	// Timezone
	loc := time.Local
	if tz := strings.TrimSpace(cfg.Timezone); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		} else {
			log.Printf("⚠️ TIMEZONE %q invalide: %v (fallback Local)", tz, err)
		}
	}

	// Valeur par défaut si REFERENCE est absente/vide
	reference := "VISOR"
	if v := strings.TrimSpace(cfg.Reference); v != "" {
		reference = v
	}
	log.Printf("Realtime: REFERENCE=%q ; ANALOG IN=%s ; DIGIT IN=%s ; OUT=%s", reference, *csvAnalogPath, *csvDigitPath, *outDir)

	// 2) Lire NodeIDs des deux CSV
	var (
		nodeIDsAnalog, displayAnalog []string
		nodeIDsDigit, displayDigit   []string
	)

	if _, err := os.Stat(*csvAnalogPath); err == nil {
		var errA error
		nodeIDsAnalog, displayAnalog, errA = readTagSpecsCSV(*csvAnalogPath)
		if errA != nil {
			log.Printf("⚠️ Erreur lecture CSV ANALOG (%s): %v", *csvAnalogPath, errA)
		}
	} else {
		log.Printf("⚠️ CSV ANALOG introuvable: %s", *csvAnalogPath)
	}

	if _, err := os.Stat(*csvDigitPath); err == nil {
		var errD error
		nodeIDsDigit, displayDigit, errD = readTagSpecsCSV(*csvDigitPath)
		if errD != nil {
			log.Printf("⚠️ Erreur lecture CSV DIGIT (%s): %v", *csvDigitPath, errD)
		}
	} else {
		log.Printf("⚠️ CSV DIGIT introuvable: %s", *csvDigitPath)
	}

	if len(nodeIDsAnalog) == 0 && len(nodeIDsDigit) == 0 {
		return fmt.Errorf("aucune NodeId à lire (CSV ANALOG et DIGIT vides ou introuvables)")
	}

	// 3) Construire options client
	var opts []opcua.Option
	if strings.EqualFold(*policy, "None") && strings.EqualFold(*mode, "None") && strings.EqualFold(*auth, "Anonymous") {
		// Connexion directe None/None/Anonymous
		opts = []opcua.Option{
			opcua.SecurityMode(ua.MessageSecurityModeNone),
			opcua.SecurityPolicy(ua.SecurityPolicyURINone),
			opcua.AuthAnonymous(),
		}
		if *certfile == "" && !*gencert {
			opts = append(opts, opcua.ApplicationURI(*appuri))
		}
	} else {
		// Chemin "sécurisé": discovery + SecurityFromEndpoint
		discCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		endpoints, err := opcua.GetEndpoints(discCtx, *endpoint)
		if err != nil {
			return fmt.Errorf("GetEndpoints: %w", err)
		}
		if *list {
			printEndpointOptions(endpoints)
			return nil
		}
		opts = clientOptsFromFlags(endpoints)
	}

	// 4) Connexion
	c, err := opcua.NewClient(*endpoint, opts...)
	if err != nil {
		return fmt.Errorf("NewClient: %w", err)
	}
	if err := c.Connect(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer c.Close(ctx)

	// 5) Requêtes de lecture séparées
	var reqAnalog *ua.ReadRequest
	if len(nodeIDsAnalog) > 0 {
		reqAnalog = &ua.ReadRequest{
			MaxAge: 2000,
			NodesToRead: func() []*ua.ReadValueID {
				list := make([]*ua.ReadValueID, len(nodeIDsAnalog))
				for i, id := range nodeIDsAnalog {
					list[i] = &ua.ReadValueID{NodeID: ua.MustParseNodeID(id)}
				}
				return list
			}(),
			TimestampsToReturn: ua.TimestampsToReturnBoth,
		}
	}

	var reqDigit *ua.ReadRequest
	if len(nodeIDsDigit) > 0 {
		reqDigit = &ua.ReadRequest{
			MaxAge: 2000,
			NodesToRead: func() []*ua.ReadValueID {
				list := make([]*ua.ReadValueID, len(nodeIDsDigit))
				for i, id := range nodeIDsDigit {
					list[i] = &ua.ReadValueID{NodeID: ua.MustParseNodeID(id)}
				}
				return list
			}(),
			TimestampsToReturn: ua.TimestampsToReturnBoth,
		}
	}

	// 6) Deux loggers CSV (ANALOG + DIGIT)
	loggerAnalog := NewCSVLogger(*outDir, "ANALOG")
	loggerDigit := NewCSVLogger(*outDir, "DIGIT")

	// 7) Boucle d’échantillonnage
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now().In(loc)
		_, wk := now.ISOWeek()
		yr := now.Year()

		// ANALOG
		if reqAnalog != nil {
			resp, err := c.Read(ctx, reqAnalog)
			if err != nil {
				log.Printf("ANALOG read failed: %v", err)
			} else {
				payload := extractTagValuesIndexed(nodeIDsAnalog, displayAnalog, resp.Results, now)
				headers := append([]string{"_time", "weekNumber", "yearNumber"}, displayAnalog...)
				if err := loggerAnalog.rotateIfNeeded(reference, wk, yr, headers); err != nil {
					log.Printf("ANALOG rotation failed: %v", err)
				} else {
					values := make([]string, len(headers))
					for i, h := range headers {
						if i == 0 {
							values[i] = payload["_time"]
						} else if h == "weekNumber" {
							values[i] = strconv.Itoa(wk)
						} else if h == "yearNumber" {
							values[i] = strconv.Itoa(yr)
						} else {
							values[i] = payload[h]
						}
					}
					if err := loggerAnalog.writeRow(values); err != nil {
						log.Printf("ANALOG write failed: %v", err)
					}
				}
			}
		}

		// DIGIT
		if reqDigit != nil {
			resp, err := c.Read(ctx, reqDigit)
			if err != nil {
				log.Printf("DIGIT read failed: %v", err)
			} else {
				payload := extractTagValuesIndexed(nodeIDsDigit, displayDigit, resp.Results, now)
				headers := append([]string{"_time", "weekNumber", "yearNumber"}, displayDigit...)
				if err := loggerDigit.rotateIfNeeded(reference, wk, yr, headers); err != nil {
					log.Printf("DIGIT rotation failed: %v", err)
				} else {
					values := make([]string, len(headers))
					for i, h := range headers {
						if i == 0 {
							values[i] = payload["_time"]
						} else if h == "weekNumber" {
							values[i] = strconv.Itoa(wk)
						} else if h == "yearNumber" {
							values[i] = strconv.Itoa(yr)
						} else {
							values[i] = payload[h]
						}
					}
					if err := loggerDigit.writeRow(values); err != nil {
						log.Printf("DIGIT write failed: %v", err)
					}
				}
			}
		}
	}
	// jamais atteint (boucle infinie)
	// si jamais tu sors de la boucle, renvoie nil
	return nil
}

// ===== Sécurité avancée (utilisée uniquement si tu changes les flags) =====

func clientOptsFromFlags(endpoints []*ua.EndpointDescription) []opcua.Option {
	opts := []opcua.Option{}

	// ApplicationURI si pas de cert
	if *certfile == "" && !*gencert {
		opts = append(opts, opcua.ApplicationURI(*appuri))
	}

	var cert []byte
	var privateKey *rsa.PrivateKey
	if *gencert || (*certfile != "" && *keyfile != "") {
		if *gencert {
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
				log.Fatalf("failed to decode PEM certificate")
			}
			_ = os.WriteFile("/etc/opcua/certificate.der", block.Bytes, 0644)
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
	case strings.HasPrefix(*policy, ua.SecurityPolicyURIPrefix):
		secPolicy = *policy
		*policy = ""
	case *policy == "None" || *policy == "Basic128Rsa15" || *policy == "Basic256" || *policy == "Basic256Sha256" || *policy == "Aes128_Sha256_RsaOaep" || *policy == "Aes256_Sha256_RsaPss":
		secPolicy = ua.SecurityPolicyURIPrefix + *policy
		*policy = ""
	default:
		log.Fatalf("Invalid security policy: %s", *policy)
	}

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

	if secMode == ua.MessageSecurityModeNone || secPolicy == ua.SecurityPolicyURINone {
		secMode = ua.MessageSecurityModeNone
		secPolicy = ua.SecurityPolicyURINone
	}

	var serverEndpoint *ua.EndpointDescription
	switch {
	case *mode == "auto" && *policy == "auto":
		for _, e := range endpoints {
			if serverEndpoint == nil || (e.SecurityMode >= serverEndpoint.SecurityMode && e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	case *mode != "auto" && *policy == "auto":
		for _, e := range endpoints {
			if e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	case *mode == "auto" && *policy != "auto":
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	default:
		for _, e := range endpoints {
			if e.SecurityPolicyURI == secPolicy && e.SecurityMode == secMode && (serverEndpoint == nil || e.SecurityLevel >= serverEndpoint.SecurityLevel) {
				serverEndpoint = e
			}
		}
	}

	if serverEndpoint == nil {
		log.Printf("unable to find suitable server endpoint with selected sec-policy and sec-mode")
		printEndpointOptions(endpoints)
		log.Fatalf("quitting")
	}

	if err := validateEndpointConfig(endpoints, serverEndpoint.SecurityPolicyURI, serverEndpoint.SecurityMode, authMode); err != nil {
		log.Fatalf("error validating input: %s", err)
	}

	opts = append(opts, opcua.SecurityFromEndpoint(serverEndpoint, authMode))
	log.Printf("Using config:\nEndpoint: %s\nSecurity mode: %s, %s\nAuth mode : %s\n",
		serverEndpoint.EndpointURL, serverEndpoint.SecurityPolicyURI, serverEndpoint.SecurityMode, authMode)
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
		authOptions = append(authOptions, opcua.AuthCertificate(cert))
		authOptions = append(authOptions, opcua.AuthPrivateKey(pk))

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
	log.Print("         sec-policy    |    sec-mode     |      auth-modes")
	log.Print("\n-----------------------|-----------------|---------------------------")
	for _, e := range endpoints {
		p := strings.TrimPrefix(e.SecurityPolicyURI, "http://opcfoundation.org/UA/SecurityPolicy#")
		m := strings.TrimPrefix(e.SecurityMode.String(), "MessageSecurityMode")
		var tt []string
		for _, t := range e.UserIdentityTokens {
			tok := strings.TrimPrefix(t.TokenType.String(), "UserTokenType")
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
		log.Printf("\n%22s | %-15s | (%s)", p, m, strings.Join(tt, ","))
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
