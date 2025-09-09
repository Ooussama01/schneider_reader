# 📊 Schneider Reader Logger

Un outil développé en Go pour lire des données depuis un automate **Schneider Electric** via le protocole **Ethernet/IP (CIP)** et les enregistrer automatiquement dans un fichier **CSV**. Ce projet est conçu pour fonctionner en continu, avec la possibilité d’être **déployé via Docker**.

---

## 🚀 Fonctionnalités

- Connexion automatique à l'automate (ex: `192.168.2.105`)
- Lecture des valeurs binaires/analogiques sur des instances spécifiques
- Enregistrement des données avec horodatage dans **data_log.csv**
- Déploiement possible dans un conteneur Docker
- Gestion automatique des erreurs et reconnexion

---

## 📦 Prérequis

- [Docker](https://www.docker.com/) installé
- L’automate Schneider configuré pour accepter les connexions **Ethernet/IP**
- Chemin vers un fichier `data_log.csv` local si on veut monter un volume Docker

---

## 🐳 Utilisation avec Docker

```bash
# 1. Construction de l’image
docker build -t schneider-reader .

# 2. Exécution du conteneur avec montage du fichier CSV local
docker run -d --name reader-instance `
  -v "C:\chemin\vers\data_log.csv:/app/data_log.csv" `
  schneider-reader

---

## 🧱 Structure du projet

schneider_reader/
├── main.go          # Code source principal (Go)
├── Dockerfile       # Instructions de build Docker
└── data_log.csv     # Fichier généré automatiquement avec les mesures


