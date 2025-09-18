// history_client.go
// Lecture HISTORIQUE seule, pilotée par opcua_client/config.json
// Par défaut: endpoint 127.0.0.1:48010, Security None/None, Auth Anonymous.

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
	endpoint   = flag.String("endpoint", "opc.tcp://127.0.0.1:48010", "OPC UA Endpoint URL (sera remplacé par config.json si présent)")
	certfile   = flag.String("cert", "C:/Users/oouachani/Downloads/certs(corridiona_new)/certs(corridiona_new)/uaexpert.pem", "Path to certificate file")
	keyfile    = flag.String("key", "C:/Users/oouachani/Downloads/certs(corridiona_new)/certs(corridiona_new)/uaexpert_key.pem", "Path to PEM Private Key file")
	gencert    = flag.Bool("gen-cert", false, "Generate a new certificate")
	policy     = flag.String("sec-policy", "None", "Security Policy: None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128_Sha256_RsaOaep, Aes256_Sha256_RsaPss")
	mode       = flag.String("sec-mode", "None", "Security Mode: None, Sign, SignAndEncrypt")
	auth       = flag.String("auth-mode", "Anonymous", "Authentication: Anonymous, UserName, Certificate")
	appuri     = flag.String("app-uri", "urn:gopcua:client", "Application URI")
	list       = flag.Bool("list", false, "List endpoint security options and exit")
	username   = flag.String("user", "", "Username for auth-mode UserName")
	password   = flag.String("pass", "", "Password for auth-mode UserName")
	outDir     = flag.String("out", "C:/Users/oouachani/Documents/csv_files", "Output CSV directory")
	configPath = flag.String("config", "C:/Users/oouachani/Documents/ats_soft/opcua_client/config.json", "Path to history config JSON")
)

// ====== Config JSON ======
type HistConfig struct {
	Endpoint  string   `json:"endpoint"`
	NodeIDs   []string `json:"nodeIds"`
	Start     string   `json:"start"`            // RFC3339
	End       string   `json:"end"`              // RFC3339
	Limit     uint32   `json:"limit,omitempty"`  // 0 = pas de limite
	Bounds    bool     `json:"bounds,omitempty"` // return bounds
	Reference string   `json:"REFERENCE,omitempty"`
	Timezone  string   `json:"TIMEZONE,omitempty"`
	Retention int      `json:"RETENTION,omitempty"`
}

// ===== CSV LOGGER (même logique que temps réel) =====
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

// NewCSVLogger crée un logger CSV qui écrira dans le dossier 'dir' avec un suffixe de "bucket"
// (ici "HIST"). Ne fait qu'initialiser la structure, n'ouvre pas de fichier.
func NewCSVLogger(dir, bucket string) *CSVLogger { return &CSVLogger{dir: dir, bucket: bucket} }

// rotateIfNeeded ouvre (ou ré-ouvre) le fichier CSV si la "référence", la semaine ou l'année changent.
// Ici pour l'historique on force week=0 et year=0 ⇒ un seul fichier par exécution.
// La fonction vérifie/écrit aussi l'entête (séparateur ';' compatible Excel FR).
func (l *CSVLogger) rotateIfNeeded(ref string, week, year int, headers []string) error {
	if l.file == nil || l.curRef != ref || l.curWeek != week || l.curYear != year {
		if l.file != nil {
			l.writer.Flush()
			_ = l.file.Close()
		}
		filename := fmt.Sprintf("%s_%s_Y%d_W%d.csv", ref, l.bucket, year, week) // pour l'histo: Y0/W0 => 1 seul fichier
		path := filepath.Join(l.dir, filename)

		if err := os.MkdirAll(l.dir, 0755); err != nil {
			return fmt.Errorf("create dir: %w", err)
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
		l.curRef = ref
		l.curWeek = week
		l.curYear = year
		l.headers = headers
	}
	return nil
}

// equalStringSlices compare deux slices de chaînes (même longueur & mêmes valeurs).
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

// writeRow écrit une ligne dans le CSV courant et flush immédiatement.
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

// main initialise le logging + flags et lance une exécution unique d'historique.
func main() {
	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()

	// log rotation
	log.SetOutput(&lumberjack.Logger{
		Filename:   "C:/Users/oouachani/Downloads/opcua_client.log",
		MaxSize:    5,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   false,
	})
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	if err := runHistoryOnce(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

// runHistoryOnce lit le JSON de config, prépare la connexion OPC UA,
// récupère les données historiques sur la période demandée et les écrit en CSV.
func runHistoryOnce() error {
	ctx := context.Background()

	// 1) Charger config JSON dans la struct pour la logique courante
	cfg, err := loadHistConfig(*configPath)
	if err != nil {
		return err
	}

	// 1bis) Lire aussi le JSON brut en map pour vérifier/mettre à jour HISTORIAN
	rawBytes, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var rawMap map[string]any
	_ = json.Unmarshal(rawBytes, &rawMap) // tolérant : si ça échoue, rawMap restera nil

	// Déterminer si HISTORIAN est true (accepte bool, "true"/"false", 1/0)
	historian := false
	if v, ok := rawMap["HISTORIAN"]; ok {
		switch t := v.(type) {
		case bool:
			historian = t
		case string:
			historian = strings.EqualFold(strings.TrimSpace(t), "true")
		case float64: // JSON numbers arrivent en float64
			historian = t != 0
		}
	}
	// Si HISTORIAN=false -> on ne fait rien
	if !historian {
		log.Println("HISTORIAN=false dans config.json : rien à faire.")
		return nil
	}

	// Toujours remettre HISTORIAN=false à la fin (bouton one-shot)
	defer func() {
		if rawMap == nil {
			return
		}
		rawMap["HISTORIAN"] = false
		out, err := json.MarshalIndent(rawMap, "", "  ")
		if err != nil {
			log.Printf("⚠️ marshal config pour HISTORIAN=false: %v", err)
			return
		}
		tmp := *configPath + ".tmp"
		if err := os.WriteFile(tmp, out, 0644); err != nil {
			log.Printf("⚠️ write tmp config: %v", err)
			return
		}
		_ = os.Remove(*configPath) // Windows-friendly
		if err := os.Rename(tmp, *configPath); err != nil {
			log.Printf("⚠️ rename tmp -> config: %v", err)
			return
		}
		log.Printf("HISTORIAN repassé à false dans %s.", *configPath)
	}()

	// Rétention logs si défini
	if cfg.Retention > 0 {
		log.SetOutput(&lumberjack.Logger{
			Filename:   "C:/Users/oouachani/Downloads/opcua_client.log",
			MaxSize:    5,
			MaxBackups: 3,
			MaxAge:     cfg.Retention,
			Compress:   false,
		})
	}

	// Endpoint depuis JSON si présent
	end := strings.TrimSpace(cfg.Endpoint)
	if end == "" {
		end = *endpoint
	}

	// Timezone
	loc := time.Local
	if tz := strings.TrimSpace(cfg.Timezone); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		} else {
			log.Printf("⚠️ TIMEZONE %q invalide: %v — fallback Local", tz, err)
		}
	}

	// Période (RFC3339)
	if strings.TrimSpace(cfg.Start) == "" || strings.TrimSpace(cfg.End) == "" {
		return fmt.Errorf("config.json: 'start' et 'end' sont requis (RFC3339)")
	}
	start, err := time.Parse(time.RFC3339, cfg.Start)
	if err != nil {
		return fmt.Errorf("start invalide (%q): %v", cfg.Start, err)
	}
	endT, err := time.Parse(time.RFC3339, cfg.End)
	if err != nil {
		return fmt.Errorf("end invalide (%q): %v", cfg.End, err)
	}
	if endT.Before(start) {
		start, endT = endT, start
	}

	// NodeIDs requis
	if len(cfg.NodeIDs) == 0 {
		return fmt.Errorf("config.json: 'nodeIds' est vide")
	}

	// 2) Options client (None/None/Anonymous direct, sinon découverte + config)
	var opts []opcua.Option
	if strings.EqualFold(*policy, "None") && strings.EqualFold(*mode, "None") && strings.EqualFold(*auth, "Anonymous") {
		opts = []opcua.Option{
			opcua.SecurityMode(ua.MessageSecurityModeNone),
			opcua.SecurityPolicy(ua.SecurityPolicyURINone),
			opcua.AuthAnonymous(),
		}
		if *certfile == "" && !*gencert {
			opts = append(opts, opcua.ApplicationURI(*appuri))
		}
	} else {
		discCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		endpoints, err := opcua.GetEndpoints(discCtx, end)
		if err != nil {
			return fmt.Errorf("GetEndpoints: %w", err)
		}
		if *list {
			printEndpointOptions(endpoints)
			return nil
		}
		opts = clientOptsFromFlags(endpoints)
	}

	// 3) Connexion au serveur OPC UA
	c, err := opcua.NewClient(end, opts...)
	if err != nil {
		return fmt.Errorf("NewClient: %w", err)
	}
	if err := c.Connect(ctx); err != nil {
		return fmt.Errorf("connect: %v", err)
	}
	defer c.Close(ctx)

	// 4) Lecture Historique
	rows, err := historyReadRawBetween(ctx, c, cfg.NodeIDs, start, endT, cfg.Limit, cfg.Bounds)
	if err != nil {
		return fmt.Errorf("HistoryRead: %w", err)
	}
	if len(rows) == 0 {
		log.Println("⚠️ Aucune donnée historique trouvée (vérifie Historizing, période et/ou bounds=true).")
		// Le defer remettra quand même HISTORIAN=false
		return nil
	}

	// 5) Écriture CSV (un seul fichier : REFERENCE_HIST_Y0_W0.csv)
	ref := strings.TrimSpace(cfg.Reference)
	if ref == "" {
		ref = "HISTORY"
	}
	logger := NewCSVLogger(*outDir, "HIST")
	headers := []string{"_time", "weekNumber", "yearNumber", "nodeId", "displayName", "value"}
	if err := logger.rotateIfNeeded(ref, 0, 0, headers); err != nil {
		return fmt.Errorf("open CSV: %w", err)
	}

	for _, r := range rows {
		ts := r.SourceTimestamp.In(loc)
		year, week := ts.ISOWeek()
		record := []string{
			ts.Format("2006-01-02 15:04:05"),
			strconv.Itoa(week),
			strconv.Itoa(year),
			r.NodeID,
			r.NodeID, // displayName = NodeID (pas d'alias dans ce client)
			fmt.Sprintf("%v", r.Value),
		}
		if err := logger.writeRow(record); err != nil {
			log.Printf("write CSV failed: %v", err)
		}
	}

	log.Printf("✅ Historique terminé : %d points écrits entre %s et %s.", len(rows), start.Format(time.RFC3339), endT.Format(time.RFC3339))
	// Le defer s'occupe de repasser HISTORIAN=false
	return nil
}

// HistRow représente une ligne de résultat historique: NodeID + timestamp source + valeur décodée.
type HistRow struct {
	NodeID          string
	SourceTimestamp time.Time
	Value           any
}

// loadHistConfig lit et parse le fichier JSON de configuration d'historique.
func loadHistConfig(path string) (HistConfig, error) {
	var cfg HistConfig
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("lecture %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse JSON %s: %w", path, err)
	}
	return cfg, nil
}

// historyReadRawBetween fait des appels OPC UA HistoryRead (raw) avec pagination
// par nœud (ContinuationPoint) entre 'start' et 'end'. Retourne toutes les lignes (tous nœuds).
func historyReadRawBetween(ctx context.Context, c *opcua.Client, nodeIDs []string, start, end time.Time, limit uint32, bounds bool) ([]HistRow, error) {
	if end.Before(start) {
		start, end = end, start
	}
	nodes := make([]*ua.HistoryReadValueID, len(nodeIDs))
	for i, s := range nodeIDs {
		id, err := ua.ParseNodeID(s)
		if err != nil {
			return nil, fmt.Errorf("NodeId invalide %q: %w", s, err)
		}
		nodes[i] = &ua.HistoryReadValueID{NodeID: id, DataEncoding: &ua.QualifiedName{}}
	}
	details := &ua.ReadRawModifiedDetails{
		IsReadModified:   false,
		StartTime:        start,
		EndTime:          end,
		NumValuesPerNode: limit,
		ReturnBounds:     bounds,
	}

	var out []HistRow
	for len(nodes) > 0 {
		resp, err := c.HistoryReadRawModified(ctx, nodes, details)
		if err != nil {
			return out, fmt.Errorf("HistoryReadRequest: %w", err)
		}
		if resp == nil || len(resp.Results) == 0 {
			break
		}

		var next []*ua.HistoryReadValueID
		for i, res := range resp.Results {
			if res.StatusCode != ua.StatusOK {
				if res.StatusCode == ua.StatusBadHistoryOperationUnsupported {
					return out, fmt.Errorf("l'historique n'est pas supporté pour %s", nodeIDs[i])
				}
				continue
			}
			// pagination par nœud
			if len(res.ContinuationPoint) > 0 {
				cp := *nodes[i]
				cp.ContinuationPoint = res.ContinuationPoint
				next = append(next, &cp)
			}
			if res.HistoryData == nil || res.HistoryData.Value == nil {
				continue
			}
			hd, ok := res.HistoryData.Value.(*ua.HistoryData)
			if !ok || hd == nil || len(hd.DataValues) == 0 {
				continue
			}
			for _, dv := range hd.DataValues {
				if dv == nil || dv.Value == nil {
					continue
				}
				if ua.StatusCode(dv.Status) != ua.StatusOK {
					continue
				}
				out = append(out, HistRow{
					NodeID:          nodes[i].NodeID.String(),
					SourceTimestamp: dv.SourceTimestamp,
					Value:           dv.Value.Value(),
				})
			}
		}
		nodes = next
	}
	return out, nil
}

// setHistorianFalse met HISTORIAN=false dans le JSON sans toucher aux autres champs.
func setHistorianFalse(path string) error {
	// Lire le JSON existant
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	// Parser dans une map pour préserver les champs inconnus
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	// Mettre à false (si absent, on l'ajoute)
	m["HISTORIAN"] = false

	// Ré-encoder joliment
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	// Écrire de façon sûre via un fichier temporaire puis rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	// Sur Windows, os.Rename échoue si le fichier existe déjà — on supprime d’abord
	_ = os.Remove(path)
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename tmp -> config: %w", err)
	}

	return nil
}

// clientOptsFromFlags reconstruit les options de sécurité/auth à partir des flags,
// en sélectionnant le meilleur endpoint compatible coté serveur (via GetEndpoints).
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
	log.Printf("Using config:\nEndpoint: %s\nSecurity mode: %s, %s\nAuth mode : %s\n", serverEndpoint.EndpointURL, serverEndpoint.SecurityPolicyURI, serverEndpoint.SecurityMode, authMode)
	return opts
}

// authFromFlags construit l’option d’authentification (Anonymous, Username/Password,
// Certificate) à partir des flags (avec prompt si nécessaire pour username/password).
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
				log.Fatalf("error reading username: %s", err)
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

// validateEndpointConfig vérifie qu’il existe bien un endpoint serveur qui matche
// le couple (policy, mode) et accepte le type d’authentification choisi.
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

// printEndpointOptions affiche les combinaisons security policy/mode/auth supportées
// par le serveur (utile pour choisir la bonne conf quand on n’est pas en None/None/Anonymous).
func printEndpointOptions(endpoints []*ua.EndpointDescription) {
	log.Print("Valid options for the endpoint are:")
	log.Print("         sec-policy    |    sec-mode     |      auth-modes\n")
	log.Print("-----------------------|-----------------|---------------------------")
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
