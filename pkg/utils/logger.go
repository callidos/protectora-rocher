package utils

import (
	"bytes"
	"os"

	"github.com/sirupsen/logrus"
)

// Initialisation du logger
var log = logrus.New()

// InitLogger initialise le logger et configure la sortie vers un fichier
func InitLogger(logFile string) (*os.File, error) {
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	log.SetOutput(file)
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)

	log.Info("Logger initialisé avec succès")
	return file, nil
}

// LogInfo enregistre un message de niveau info avec des champs supplémentaires
func LogInfo(message string, fields map[string]interface{}) {
	log.WithFields(fields).Info(message)
}

// LogWarning enregistre un message de niveau warning avec des champs supplémentaires
func LogWarning(message string, fields map[string]interface{}) {
	log.WithFields(fields).Warn(message)
}

// LogError enregistre un message de niveau erreur avec des champs supplémentaires
func LogError(message string, fields map[string]interface{}) {
	log.WithFields(fields).Error(message)
}

// LogDebug enregistre un message de niveau debug avec des champs supplémentaires
func LogDebug(message string, fields map[string]interface{}) {
	log.WithFields(fields).Debug(message)
}

// SetLogLevel permet de modifier dynamiquement le niveau de log
func SetLogLevel(level string) {
	switch level {
	case "debug":
		log.SetLevel(logrus.DebugLevel)
	case "info":
		log.SetLevel(logrus.InfoLevel)
	case "warn":
		log.SetLevel(logrus.WarnLevel)
	case "error":
		log.SetLevel(logrus.ErrorLevel)
	default:
		log.SetLevel(logrus.InfoLevel)
	}
}

// SetLoggerOutput permet de rediriger la sortie du logger vers un buffer pour les tests
func SetLoggerOutput(output *bytes.Buffer) {
	log.SetOutput(output)
}
