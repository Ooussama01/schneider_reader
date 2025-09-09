// Client OPC UA - Lecture d'historique entre deux dates via config.json
// ⚠️ Recommandé avec github.com/gopcua/opcua v0.7.6 (API HistoryReadRawModified).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/ua"
)

type Config struct {
	Endpoint string `json:"endpoint"`         // ex: "opc.tcp://192.168.1.57:48010"
	NodeID   string `json:"nodeId"`           // ex: "ns=3;s=Demo.History.Historian_1"
	Start    string `json:"start"`            // ex: "2019-08-22T00:00:00Z" (RFC3339 UTC)
	End      string `json:"end"`              // ex: "2019-08-24T23:59:59Z" (RFC3339 UTC)
	Limit    uint32 `json:"limit,omitempty"`  // ex: 10000
	Bounds   bool   `json:"bounds,omitempty"` // true pour ReturnBounds
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("lecture %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse JSON %s: %w", path, err)
	}

	return cfg, nil
}

func main() {
	log.SetFlags(0)

	// 1) Charger la configuration
	cfg, err := loadConfig("config.json")
	if err != nil {
		log.Fatal(err)
	}

	// 2) Période
	start, err := time.Parse(time.RFC3339, cfg.Start)
	if err != nil {
		log.Fatalf("start invalide (%q): %v", cfg.Start, err)
	}
	end, err := time.Parse(time.RFC3339, cfg.End)
	if err != nil {
		log.Fatalf("end invalide (%q): %v", cfg.End, err)
	}
	// Corriger si dates inversées
	if end.Before(start) {
		start, end = end, start
	}

	// 3) Connexion OPC UA
	ctx := context.Background()
	c, err := opcua.NewClient(cfg.Endpoint, opcua.SecurityMode(ua.MessageSecurityModeNone))
	if err != nil {
		log.Fatalf("création client: %v", err)
	}
	if err := c.Connect(ctx); err != nil {
		log.Fatalf("connexion OPC UA: %v", err)
	}
	defer c.Close(ctx)

	// 4) NodeId
	id, err := ua.ParseNodeID(cfg.NodeID)
	if err != nil {
		log.Fatalf("NodeId invalide (%q): %v", cfg.NodeID, err)
	}

	// 5) Première requête (ContinuationPoint vide)
	nodes := []*ua.HistoryReadValueID{
		{NodeID: id, DataEncoding: &ua.QualifiedName{}},
	}

	total := 0
	page := 0

	for len(nodes) > 0 {
		page++

		details := &ua.ReadRawModifiedDetails{
			IsReadModified:   false, // ReadRaw
			StartTime:        start,
			EndTime:          end,
			NumValuesPerNode: cfg.Limit,
			ReturnBounds:     cfg.Bounds, // false = pas de bornes <nil>
		}

		// 6) Appel HistoryRead (API v0.7.6)
		data, err := c.HistoryReadRawModified(ctx, nodes, details)
		if err != nil {
			log.Fatalf("HistoryReadRequest error: %v", err)
		}
		if data == nil || len(data.Results) == 0 {
			break
		}

		var next []*ua.HistoryReadValueID

		for i, res := range data.Results {
			// Statut du serveur
			if res.StatusCode != ua.StatusOK {
				log.Printf("⚠️ result[%d] status: %s", i, res.StatusCode)
				if res.StatusCode == ua.StatusBadHistoryOperationUnsupported {
					log.Println("❌ Le serveur/nœud ne supporte pas la lecture historique (HDA) pour ce NodeId.")
				}
				continue
			}

			// Pagination serveur via ContinuationPoint
			if len(res.ContinuationPoint) > 0 {
				cp := *nodes[i]
				cp.ContinuationPoint = res.ContinuationPoint
				next = append(next, &cp)
			}

			// Décodage ExtensionObject -> ua.HistoryData
			if res.HistoryData == nil || res.HistoryData.Value == nil {
				continue
			}
			hd, ok := res.HistoryData.Value.(*ua.HistoryData)
			if !ok || hd == nil || len(hd.DataValues) == 0 {
				continue
			}

			// 7) Affichage: ignorer valeurs vides / statuts non-OK
			for _, dv := range hd.DataValues {
				if dv == nil || dv.Value == nil {
					continue
				}
				// v0.7.6: champ "Status" (pas "StatusCode")
				if ua.StatusCode(dv.Status) != ua.StatusOK {
					continue
				}
				total++
				fmt.Printf("%s | %s | %v\n",
					nodes[i].NodeID.String(),
					dv.SourceTimestamp.Format(time.RFC3339),
					dv.Value.Value(),
				)
			}
		}

		// Requête suivante si CP
		nodes = next
	}

	if total == 0 {
		log.Println("⚠️ Aucune donnée historique trouvée.")
		log.Println("• Vérifie que le nœud est historisé (Historizing=true) côté serveur.")
		log.Println("• Utilise une période start/end où il y a des données.")
		log.Println("• Mets \"bounds\": true dans le config si tu veux voir les bornes.")
	} else {
		log.Printf("✅ Terminé : %d valeurs lues en %d page(s).", total, page)
	}
}
