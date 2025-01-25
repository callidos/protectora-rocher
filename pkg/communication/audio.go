package communication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"protectora-rocher/pkg/utils"

	"github.com/pion/webrtc/v4"
)

func StartSecureCall(conn io.ReadWriter, sharedKey []byte) error {
	config := webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	peerConnection, err := webrtc.NewPeerConnection(config)
	if err != nil {
		return fmt.Errorf("erreur lors de la création de la connexion WebRTC : %v", err)
	}
	defer func() {
		if err := peerConnection.Close(); err != nil {
			utils.Logger.Error("Erreur lors de la fermeture de la connexion WebRTC", map[string]interface{}{
				"error": err,
			})
		}
	}()

	dataChannel, err := peerConnection.CreateDataChannel("secure-audio", nil)
	if err != nil {
		return fmt.Errorf("erreur lors de la création du DataChannel sécurisé : %v", err)
	}

	dataChannel.OnOpen(func() {
		utils.Logger.Info("Canal de données sécurisé ouvert", map[string]interface{}{})
	})

	dataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
		utils.Logger.Debug("Message reçu via le canal sécurisé", map[string]interface{}{
			"data": string(msg.Data),
		})
	})

	peerConnection.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		if track == nil {
			utils.Logger.Error("La piste audio est nulle", map[string]interface{}{})
			return
		}

		utils.Logger.Info("Piste audio reçue", map[string]interface{}{
			"track_id": track.ID(),
		})

		go func() {
			if err := HandleSecureAudioStream(conn, sharedKey, track); err != nil {
				utils.Logger.Error("Erreur lors du traitement du flux audio sécurisé", map[string]interface{}{
					"error": err,
				})
			}
		}()
	})

	peerConnection.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		utils.Logger.Info("État de la connexion ICE", map[string]interface{}{
			"state": state.String(),
		})
	})

	peerConnection.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed {
			utils.Logger.Error("Échec de la connexion WebRTC", map[string]interface{}{})
		}
	})

	utils.Logger.Info("Appel vocal sécurisé démarré", map[string]interface{}{})
	return nil
}

func HandleSecureAudioStream(writer io.Writer, key []byte, track *webrtc.TrackRemote) error {
	if writer == nil || track == nil {
		return fmt.Errorf("writer ou track est nil")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("échec de la création du chiffrement : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("échec de la création de l'AES-GCM : %v", err)
	}

	for {
		sample, _, err := track.ReadRTP()
		if err != nil {
			if err == io.EOF {
				utils.Logger.Info("Fin du flux audio", map[string]interface{}{})
				break
			}
			utils.Logger.Error("Erreur lors de la lecture du flux audio", map[string]interface{}{
				"error": err,
			})
			continue
		}

		nonce := make([]byte, aesGCM.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("échec de génération du nonce sécurisé : %v", err)
		}

		encrypted := aesGCM.Seal(nil, nonce, sample.Payload, nil)

		_, err = writer.Write(append(nonce, encrypted...))
		if err != nil {
			return fmt.Errorf("échec d'écriture des données audio sécurisées : %v", err)
		}

		utils.Logger.Info("Données audio chiffrées envoyées", map[string]interface{}{
			"size": len(encrypted),
		})
	}

	return nil
}

func StopSecureCall(conn io.ReadWriter, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("échec de la création du chiffrement : %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("échec de la création de l'AES-GCM : %v", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("échec de génération du nonce sécurisé : %v", err)
	}

	encryptedMessage := aesGCM.Seal(nil, nonce, []byte("END_CALL"), nil)

	_, err = conn.Write(append(nonce, encryptedMessage...))
	if err != nil {
		return fmt.Errorf("erreur lors de l'envoi du message de fin d'appel sécurisé : %v", err)
	}

	utils.Logger.Info("Appel vocal sécurisé terminé", map[string]interface{}{})
	return nil
}
