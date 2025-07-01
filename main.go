package main

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"

	go_ethernet_ip "github.com/loki-os/go-ethernet-ip"
	"github.com/loki-os/go-ethernet-ip/messages/packet"
	"github.com/loki-os/go-ethernet-ip/path"
	"github.com/loki-os/go-ethernet-ip/types"
)

func main() {
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("⚠️ Crash évité : %v. Nouvelle tentative dans 5 secondes...\n", r)
					time.Sleep(5 * time.Second)
				}
			}()

			runLogger()
		}()

		time.Sleep(5 * time.Second) // Attente avant tentative de reconnexion
	}
}

func runLogger() {
	conn, err := go_ethernet_ip.NewTCP("192.168.2.105", nil)
	if err != nil {
		log.Printf("❌ Connexion échouée : %v", err)
		return
	}
	defer conn.UnRegisterSession()

	if err := conn.Connect(); err != nil {
		log.Printf("❌ Échec de la connexion : %v", err)
		return
	}
	log.Println("✅ Connecté à l'automate")

	csvFile, err := os.OpenFile("data_log.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("❌ Impossible d’ouvrir le fichier CSV : %v", err)
		return
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	fileInfo, _ := csvFile.Stat()
	if fileInfo.Size() == 0 {
		writer.Write([]string{
			"_time", "weekNumber", "yearNumber",
			"ACC81011ADEV", "ACC81011AOUT", "ACC81011APV", "ACC81011ASP",
		})
	}

	for {
		data := readAssemblyAttribute(conn, 100, 3)

		if len(data) >= 12 {
			qwe0 := binary.LittleEndian.Uint16(data[4:6])
			qwe1 := binary.LittleEndian.Uint16(data[6:8])
			qwe2 := binary.LittleEndian.Uint16(data[8:10])
			qwe3 := binary.LittleEndian.Uint16(data[10:12])

			now := time.Now()
			yearNumber, weekNumber := now.ISOWeek()

			record := []string{
				now.Format("2006-01-02 15:04:05"),
				fmt.Sprintf("%d", weekNumber),
				fmt.Sprintf("%d", yearNumber),
				fmt.Sprintf("%d", qwe0),
				fmt.Sprintf("%d", qwe1),
				fmt.Sprintf("%d", qwe2),
				fmt.Sprintf("%d", qwe3),
			}

			writer.Write(record)
			writer.Flush()

			fmt.Printf("📝 Données enregistrées : %v\n", record)
		} else {
			log.Printf("⚠️ Données insuffisantes (%d octets). Vérifie l’automate ou le câble.\n", len(data))
		}

		time.Sleep(1 * time.Second)
	}
}

func readAssemblyAttribute(conn *go_ethernet_ip.EIPTCP, instance uint8, attribute uint8) []byte {
	pathBytes := packet.Paths(
		path.LogicalBuild(path.LogicalTypeClassID, types.UDInt(0x04), true),
		path.LogicalBuild(path.LogicalTypeInstanceID, types.UDInt(instance), true),
		path.LogicalBuild(path.LogicalTypeAttributeID, types.UDInt(attribute), true),
	)

	request := packet.NewMessageRouter(0x0E, pathBytes, nil)

	response, err := conn.Send(request)
	if err != nil {
		log.Printf("❌ Erreur CIP : %v", err)
		panic("perte de communication")
	}

	if len(response.Packet.Items) < 2 {
		log.Println("❌ Réponse CIP invalide ou incomplète")
		panic("réponse vide")
	}

	return response.Packet.Items[1].Data
}
