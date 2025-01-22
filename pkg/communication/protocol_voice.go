package communication

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/rtp"
	"github.com/pion/srtp"
)

type SRTPKeys struct {
	LocalMasterKey   []byte
	LocalMasterSalt  []byte
	RemoteMasterKey  []byte
	RemoteMasterSalt []byte
	Profile          srtp.ProtectionProfile
}

type VoiceSession struct {
	session     *srtp.SessionSRTP
	writeStream interface{ Write([]byte) (int, error) }
	sequenceNum uint16
}

func NewVoiceSession(conn net.Conn, keys *SRTPKeys) (*VoiceSession, error) {
	config := &srtp.Config{
		Keys: srtp.SessionKeys{
			LocalMasterKey:   keys.LocalMasterKey,
			LocalMasterSalt:  keys.LocalMasterSalt,
			RemoteMasterKey:  keys.RemoteMasterKey,
			RemoteMasterSalt: keys.RemoteMasterSalt,
		},
		Profile: keys.Profile,
		LocalOptions: []srtp.ContextOption{
			srtp.SRTPReplayProtection(64),
		},
		RemoteOptions: []srtp.ContextOption{
			srtp.SRTPReplayProtection(64),
		},
	}

	session, err := srtp.NewSessionSRTP(conn, config)
	if err != nil {
		return nil, fmt.Errorf("échec de la création de la session SRTP: %v", err)
	}

	writeStream, err := session.OpenWriteStream()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("échec de l'ouverture du WriteStreamSRTP: %v", err)
	}

	return &VoiceSession{
		session:     session,
		writeStream: writeStream,
		sequenceNum: 0,
	}, nil
}

func (vs *VoiceSession) SendAudioFrame(input []int16, ssrc uint32, payloadType uint8) error {
	vs.sequenceNum++

	packet := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    payloadType,
			SequenceNumber: vs.sequenceNum,
			Timestamp:      uint32(time.Now().UnixNano() / 1e6),
			SSRC:           ssrc,
		},
		Payload: Int16SliceToByteSlice(input),
	}

	rawPacket, err := packet.Marshal()
	if err != nil {
		return fmt.Errorf("erreur de sérialisation RTP: %v", err)
	}

	_, err = vs.writeStream.Write(rawPacket)
	if err != nil {
		return fmt.Errorf("erreur d'écriture SRTP: %v", err)
	}
	return nil
}

func Int16SliceToByteSlice(data []int16) []byte {
	buf := make([]byte, len(data)*2)
	for i, v := range data {
		buf[2*i] = byte(v)
		buf[2*i+1] = byte(v >> 8)
	}
	return buf
}

func (vs *VoiceSession) Close() error {
	if err := vs.session.Close(); err != nil {
		return err
	}
	return nil
}
