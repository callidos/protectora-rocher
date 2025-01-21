package utils

import (
	"log"
	"os"
)

func InitLogger(logFile string) *os.File {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Erreur d'ouverture du fichier de log: %v", err)
	}
	log.SetOutput(file)
	return file
}

func LogInfo(message string) {
	log.Println("[INFO]:", message)
}

func LogWarning(message string) {
	log.Println("[WARNING]:", message)
}

func LogError(message string) {
	log.Println("[ERROR]:", message)
}
