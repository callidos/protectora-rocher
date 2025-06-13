package tests

import (
	"bytes"
	"testing"

	"github.com/callidos/protectora-rocher/pkg/utils"
)

// MockLogger est une implémentation de LoggerInterface pour les tests.
type MockLogger struct {
	buffer *bytes.Buffer
}

func (m *MockLogger) Info(message string, fields map[string]interface{}) {
	m.log("[INFO]", message, fields)
}

func (m *MockLogger) Warning(message string, fields map[string]interface{}) {
	m.log("[WARNING]", message, fields)
}

func (m *MockLogger) Error(message string, fields map[string]interface{}) {
	m.log("[ERROR]", message, fields)
}

func (m *MockLogger) Debug(message string, fields map[string]interface{}) {
	m.log("[DEBUG]", message, fields)
}

func (m *MockLogger) log(level string, message string, fields map[string]interface{}) {
	m.buffer.WriteString(level + " " + message)
	for k, v := range fields {
		m.buffer.WriteString(" " + k + "=" + v.(string))
	}
	m.buffer.WriteString("\n")
}

// Test de la journalisation des messages de niveau info
func TestLogInfo(t *testing.T) {
	var buffer bytes.Buffer
	mockLogger := &MockLogger{buffer: &buffer}
	utils.SetLogger(mockLogger)

	utils.Logger.Info("Test info", map[string]interface{}{"key": "value"})

	logOutput := buffer.String()
	if !contains(logOutput, "[INFO] Test info") {
		t.Errorf("Le message de niveau info n'a pas été enregistré correctement")
	}
	if !contains(logOutput, "key=value") {
		t.Errorf("Les champs supplémentaires n'ont pas été enregistrés correctement")
	}
}

// Test de la journalisation des messages de niveau erreur
func TestLogError(t *testing.T) {
	var buffer bytes.Buffer
	mockLogger := &MockLogger{buffer: &buffer}
	utils.SetLogger(mockLogger)

	utils.Logger.Error("Test error", map[string]interface{}{"error": "fatal"})

	logOutput := buffer.String()
	if !contains(logOutput, "[ERROR] Test error") {
		t.Errorf("Le message de niveau erreur n'a pas été enregistré correctement")
	}
	if !contains(logOutput, "error=fatal") {
		t.Errorf("Les champs supplémentaires d'erreur n'ont pas été enregistrés correctement")
	}
}

// Test de la journalisation des messages de niveau debug
func TestLogDebug(t *testing.T) {
	var buffer bytes.Buffer
	mockLogger := &MockLogger{buffer: &buffer}
	utils.SetLogger(mockLogger)

	utils.Logger.Debug("Debug message", map[string]interface{}{"debug": "true"})

	logOutput := buffer.String()
	if !contains(logOutput, "[DEBUG] Debug message") {
		t.Errorf("Le message de niveau debug n'a pas été enregistré correctement")
	}
	if !contains(logOutput, "debug=true") {
		t.Errorf("Les champs supplémentaires de debug n'ont pas été enregistrés correctement")
	}
}

// Test de la journalisation des messages de niveau warning
func TestLogWarning(t *testing.T) {
	var buffer bytes.Buffer
	mockLogger := &MockLogger{buffer: &buffer}
	utils.SetLogger(mockLogger)

	utils.Logger.Warning("Test warning", map[string]interface{}{"warn": "attention"})

	logOutput := buffer.String()
	if !contains(logOutput, "[WARNING] Test warning") {
		t.Errorf("Le message de niveau warning n'a pas été enregistré correctement")
	}
	if !contains(logOutput, "warn=attention") {
		t.Errorf("Les champs supplémentaires d'avertissement n'ont pas été enregistrés correctement")
	}
}

// Helper pour vérifier si une chaîne contient un texte donné
func contains(output, substring string) bool {
	return bytes.Contains([]byte(output), []byte(substring))
}
