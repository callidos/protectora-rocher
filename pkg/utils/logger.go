package utils

import (
	"os"

	"github.com/sirupsen/logrus"
)

// Initialisation du logger
var log = logrus.New()

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

func LogInfo(message string, fields map[string]interface{}) {
	log.WithFields(fields).Info(message)
}

func LogWarning(message string, fields map[string]interface{}) {
	log.WithFields(fields).Warn(message)
}

func LogError(message string, fields map[string]interface{}) {
	log.WithFields(fields).Error(message)
}

func LogDebug(message string, fields map[string]interface{}) {
	log.WithFields(fields).Debug(message)
}

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
