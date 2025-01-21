package tests

import (
	"bytes"
	"os"
	"protectora-rocher/pkg/utils"
	"testing"
)

// Test de l'initialisation du logger avec un fichier
func TestInitLogger(t *testing.T) {
	logFile := "test_log.log"

	file, err := utils.InitLogger(logFile)
	if err != nil {
		t.Fatalf("Erreur lors de l'initialisation du logger : %v", err)
	}
	defer file.Close()
	defer os.Remove(logFile) // Nettoyage du fichier après le test

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Errorf("Le fichier de log n'a pas été créé")
	}
}

// Test de la journalisation des messages de niveau info
func TestLogInfo(t *testing.T) {
	var buffer bytes.Buffer
	utils.SetLoggerOutput(&buffer)

	utils.LogInfo("Test info", map[string]interface{}{"key": "value"})

	logOutput := buffer.String()
	if !contains(logOutput, `"msg":"Test info"`) {
		t.Errorf("Le message de niveau info n'a pas été enregistré correctement")
	}
	if !contains(logOutput, `"key":"value"`) {
		t.Errorf("Les champs supplémentaires n'ont pas été enregistrés correctement")
	}
}

// Test de la journalisation des messages de niveau erreur
func TestLogError(t *testing.T) {
	var buffer bytes.Buffer
	utils.SetLoggerOutput(&buffer)

	utils.LogError("Test error", map[string]interface{}{"error": "fatal"})

	logOutput := buffer.String()
	if !contains(logOutput, `"msg":"Test error"`) {
		t.Errorf("Le message de niveau erreur n'a pas été enregistré correctement")
	}
	if !contains(logOutput, `"error":"fatal"`) {
		t.Errorf("Les champs supplémentaires d'erreur n'ont pas été enregistrés correctement")
	}
}

// Test de la modification du niveau de log
func TestSetLogLevel(t *testing.T) {
	utils.SetLogLevel("debug")

	var buffer bytes.Buffer
	utils.SetLoggerOutput(&buffer)

	utils.LogDebug("Debug message", nil)
	logOutput := buffer.String()

	if !contains(logOutput, `"msg":"Debug message"`) {
		t.Errorf("Le message de niveau debug n'a pas été enregistré correctement après le changement de niveau")
	}
}

// Helper pour vérifier si une chaîne contient un texte donné
func contains(output, substring string) bool {
	return bytes.Contains([]byte(output), []byte(substring))
}
