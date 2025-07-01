# 1. Utilise une image Go légère
FROM golang:1.22-alpine

# 2. Dossier de travail dans le conteneur
WORKDIR /app

# 3. Copie les fichiers Go dans le conteneur
COPY . .

# 4. Installe les dépendances Go
RUN go mod tidy

# 5. Compile ton code en exécutable
RUN go build -o logger main.go

# 6. Lancer l’exécutable
CMD ["./logger"]
