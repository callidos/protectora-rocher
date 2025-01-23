package utils

import "fmt"

// LoggerInterface définit les méthodes de logging qui doivent être implémentées.
type LoggerInterface interface {
	Info(message string, fields map[string]interface{})
	Warning(message string, fields map[string]interface{})
	Error(message string, fields map[string]interface{})
	Debug(message string, fields map[string]interface{})
}

// DefaultLogger est une implémentation par défaut utilisant fmt.
type DefaultLogger struct{}

func (l DefaultLogger) Info(message string, fields map[string]interface{}) {
	fmt.Printf("[INFO] %s - %v\n", message, fields)
}

func (l DefaultLogger) Warning(message string, fields map[string]interface{}) {
	fmt.Printf("[WARNING] %s - %v\n", message, fields)
}

func (l DefaultLogger) Error(message string, fields map[string]interface{}) {
	fmt.Printf("[ERROR] %s - %v\n", message, fields)
}

func (l DefaultLogger) Debug(message string, fields map[string]interface{}) {
	fmt.Printf("[DEBUG] %s - %v\n", message, fields)
}

// Logger est une instance globale qui peut être remplacée si nécessaire.
var Logger LoggerInterface = DefaultLogger{}

// SetLogger permet de changer le logger utilisé par le protocole.
func SetLogger(customLogger LoggerInterface) {
	Logger = customLogger
}
