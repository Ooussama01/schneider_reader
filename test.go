// go:build ignore
// Fichier: main.go
package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
)

var (
	endpoint = flag.String("endpoint", "opc.tcp://172.16.85.25:48010", "OPC UA Endpoint URL")

	// Nodes (adapter à ton serveur)
	srcDirStr  = flag.String("srcDir", "ns=2;s=Files/incoming", "NodeId du répertoire source (instance FileDirectoryType)")
	objectStr  = flag.String("object", "ns=2;s=Files/incoming/report.csv", "NodeId du fichier/dossier à déplacer/copier")
	dstDirStr  = flag.String("dstDir", "ns=2;s=Files/archive", "NodeId du répertoire destination (instance FileDirectoryType)")
	createCopy = flag.Bool("copy", true, "true = copier, false = déplacer (move)")
	newName    = flag.String("newName", "report-2025-09-02.csv", "Nouveau nom dans la destination (laisser vide pour garder le même nom)")
	timeoutSec = flag.Int("timeout", 10, "Timeout de connexion en secondes")

	// Sécurité & Auth
	// Valeurs possibles:
	//   sec-policy: auto|None|Basic128Rsa15|Basic256|Basic256Sha256|Aes128_Sha256_RsaOaep|Aes256_Sha256_RsaPss
	//   sec-mode:   auto|None|Sign|SignAndEncrypt
	secPolicy = flag.String("sec-policy", "auto", "Politique de sécurité")
	secMode   = flag.String("sec-mode", "auto", "Mode de sécurité (None, Sign, SignAndEncrypt)")
	authMode  = flag.String("auth", "Anonymous", "Mode d'authentification: Anonymous|UserName|Certificate")
	user      = flag.String("user", "", "Nom d'utilisateur (auth=UserName)")
	pass      = flag.String("pass", "", "Mot de passe (auth=UserName)")
	certFile  = flag.String("cert", "", "Chemin du certificat client (auth=Certificate)")
	keyFile   = flag.String("key", "", "Chemin de la clé privée PEM (auth=Certificate)")
	appURI    = flag.String("app-uri", "urn:gopcua:client", "Application URI (utile si pas de cert)")
)

func main() {
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	// 1) Découverte des endpoints
	endpoints, err := opcua.GetEndpoints(ctx, *endpoint)
	if err != nil {
		log.Fatalf("GetEndpoints: %v", err)
	}
	if len(endpoints) == 0 {
		log.Fatalf("Aucun endpoint disponible sur %s", *endpoint)
	}

	// 2) Choix de l'endpoint (meilleur ou en fonction des flags sec)
	ep := selectEndpoint(endpoints, *secPolicy, *secMode)
	log.Printf("Endpoint choisi: %s | SecurityPolicy=%s | SecurityMode=%s",
		ep.EndpointURL, ep.SecurityPolicyURI, ep.SecurityMode.String())

	// 3) Auth options
	authOpts := authOptionsFromFlags()

	// 4) Création client
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, authOpts.tokenType),
	}
	opts = append(opts, authOpts.opts...)

	c, err := opcua.NewClient(ep.EndpointURL, opts...)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	// 5) Connexion
	if err := c.Connect(ctx); err != nil {
		log.Fatalf("Connect: %v", err)
	}
	defer func() {
		_ = c.Close(context.Background())
	}()

	// 6) Prépare l'appel MoveOrCopy (ns=0;i=13350)
	srcDir, err := ua.ParseNodeID(*srcDirStr)
	mustOK(err, "parse srcDir")
	obj, err := ua.ParseNodeID(*objectStr)
	mustOK(err, "parse object")
	dstDir, err := ua.ParseNodeID(*dstDirStr)
	mustOK(err, "parse dstDir")

	methodID := ua.NewNumericNodeID(0, 13350) // MoveOrCopy (standard)
	inputs := []*ua.Variant{
		mustVariant(obj),              // objectToMoveOrCopy
		mustVariant(dstDir),           // targetDirectory
		mustVariant(*createCopy),      // createCopy
		mustVariant(string(*newName)), // newName (peut être vide selon serveur — certains exigent non vide)
	}

	req := &ua.CallMethodRequest{
		ObjectID:       srcDir,   // on invoque la méthode sur le RÉPERTOIRE SOURCE (instance FileDirectoryType)
		MethodID:       methodID, // MoveOrCopy
		InputArguments: inputs,
	}

	// 7) Appel
	callResp, err := c.Call(ctx, req)
	mustOK(err, "Call MoveOrCopy")
	if callResp.StatusCode != ua.StatusOK {
		log.Fatalf("MoveOrCopy a échoué: %s", callResp.StatusCode)
	}
	if len(callResp.OutputArguments) != 1 {
		log.Fatalf("MoveOrCopy: nombre de sorties inattendu: %d", len(callResp.OutputArguments))
	}

	// 8) Récupérer le NodeId résultant
	out := callResp.OutputArguments[0].Value()
	switch v := out.(type) {
	case *ua.NodeID:
		log.Printf("✅ MoveOrCopy OK → nouveau NodeId: %s", v.String())
	case ua.NodeID:
		log.Printf("✅ MoveOrCopy OK → nouveau NodeId: %s", v.String())
	default:
		log.Printf("✅ MoveOrCopy OK → sortie inattendue (%T): %#v", out, out)
	}
}

// --- Helpers ---

func mustOK(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %v", msg, err)
	}
}

func mustVariant(v interface{}) *ua.Variant {
	vr, err := ua.NewVariant(v)
	if err != nil {
		log.Fatalf("variant(%T): %v", v, err)
	}
	return vr
}

type authBundle struct {
	opts      []opcua.Option
	tokenType ua.UserTokenType
}

func authOptionsFromFlags() authBundle {
	switch strings.ToLower(*authMode) {
	case "anonymous":
		return authBundle{
			opts:      []opcua.Option{opcua.AuthAnonymous()},
			tokenType: ua.UserTokenTypeAnonymous,
		}
	case "username":
		u := *user
		p := *pass
		if u == "" {
			fmt.Print("Enter username: ")
			r := bufio.NewReader(os.Stdin)
			line, _ := r.ReadString('\n')
			u = strings.TrimSpace(line)
		}
		if p == "" {
			fmt.Print("Enter password: ")
			b, _ := term.ReadPassword(int(syscall.Stdin))
			fmt.Println()
			p = string(b)
		}
		return authBundle{
			opts:      []opcua.Option{opcua.AuthUsername(u, p)},
			tokenType: ua.UserTokenTypeUserName,
		}
	case "certificate":
		if *certFile == "" || *keyFile == "" {
			log.Fatalf("auth=Certificate nécessite -cert et -key")
		}
		pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		mustOK(err, "chargement certificat/clé")
		pk, ok := pair.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			log.Fatalf("clé privée invalide (attendu RSA)")
		}
		// On charge aussi l'ApplicationURI si pas fournie via cert
		opts := []opcua.Option{opcua.AuthCertificate(pair.Certificate[0]), opcua.AuthPrivateKey(pk)}
		if *appURI != "" {
			opts = append(opts, opcua.ApplicationURI(*appURI))
		}
		return authBundle{
			opts:      opts,
			tokenType: ua.UserTokenTypeCertificate,
		}
	default:
		log.Printf("auth inconnu %q → Anonymous", *authMode)
		return authBundle{
			opts:      []opcua.Option{opcua.AuthAnonymous()},
			tokenType: ua.UserTokenTypeAnonymous,
		}
	}
}

func selectEndpoint(eps []*ua.EndpointDescription, policy, mode string) *ua.EndpointDescription {
	// Normalise flags
	policy = strings.TrimSpace(policy)
	mode = strings.TrimSpace(mode)

	// Helper pour vérifier mode
	matchMode := func(m ua.MessageSecurityMode) bool {
		if strings.EqualFold(mode, "auto") || mode == "" {
			return true
		}
		switch strings.ToLower(mode) {
		case "none":
			return m == ua.MessageSecurityModeNone
		case "sign":
			return m == ua.MessageSecurityModeSign
		case "signandencrypt":
			return m == ua.MessageSecurityModeSignAndEncrypt
		default:
			return true
		}
	}

	// Helper pour vérifier policy
	matchPolicy := func(p string) bool {
		if strings.EqualFold(policy, "auto") || policy == "" {
			return true
		}
		// Autoriser alias courts
		if !strings.HasPrefix(policy, ua.SecurityPolicyURIPrefix) {
			short := ua.SecurityPolicyURIPrefix + policy
			return strings.EqualFold(p, short)
		}
		return strings.EqualFold(p, policy)
	}

	var best *ua.EndpointDescription
	for _, ep := range eps {
		if !matchMode(ep.SecurityMode) || !matchPolicy(ep.SecurityPolicyURI) {
			continue
		}
		if best == nil {
			best = ep
			continue
		}
		// Choisir le plus "sécurisé" (niveau + mode)
		if ep.SecurityLevel > best.SecurityLevel ||
			(ep.SecurityLevel == best.SecurityLevel && ep.SecurityMode > best.SecurityMode) {
			best = ep
		}
	}

	// Si rien ne matche les critères, prendre le plus élevé globalement.
	if best == nil {
		for _, ep := range eps {
			if best == nil ||
				ep.SecurityLevel > best.SecurityLevel ||
				(ep.SecurityLevel == best.SecurityLevel && ep.SecurityMode > best.SecurityMode) {
				best = ep
			}
		}
	}
	return best
}

// --- (Optionnel) conversion PEM → DER si besoin ---
// Utile si tu dois extraire les bytes DER depuis un PEM déjà chargé ailleurs.
func pemToDER(pemBytes []byte) []byte {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil
	}
	return block.Bytes
}
