// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

type UClientHelloMsg struct {
	Raw                              []byte
	Vers                             uint16
	Random                           []byte
	SessionId                        []byte
	CipherSuites                     []uint16
	CompressionMethods               []uint8
	ServerName                       string
	OcspStapling                     bool
	SupportedCurves                  []CurveID
	SupportedPoints                  []uint8
	TicketSupported                  bool
	SessionTicket                    []uint8
	SupportedSignatureAlgorithms     []SignatureScheme
	SupportedSignatureAlgorithmsCert []SignatureScheme
	SecureRenegotiationSupported     bool
	SecureRenegotiation              []byte
	AlpnProtocols                    []string
	Scts                             bool
	SupportedVersions                []uint16
	Cookie                           []byte
	KeyShares                        []UKeyShare
	EarlyData                        bool
	PSKModes                         []uint8
	PSKIdentities                    []UPSKIdentity
	PSKBinders                       [][]byte

	// [uTLS]
	NextProtoNeg bool
	Ems          bool // actually implemented due to its prevalence
}

// UClientHelloMsg -> clientHelloMsg
func (uchm *UClientHelloMsg) toPrivate() *clientHelloMsg {
	if uchm == nil {
		return nil
	} else {
		return &clientHelloMsg{
			raw:                          uchm.Raw,
			vers:                         uchm.Vers,
			random:                       uchm.Random,
			sessionId:                    uchm.SessionId,
			cipherSuites:                 uchm.CipherSuites,
			compressionMethods:           uchm.CompressionMethods,
			nextProtoNeg:                 uchm.NextProtoNeg,
			serverName:                   uchm.ServerName,
			ocspStapling:                 uchm.OcspStapling,
			scts:                         uchm.Scts,
			ems:                          uchm.Ems,
			supportedCurves:              uchm.SupportedCurves,
			supportedPoints:              uchm.SupportedPoints,
			ticketSupported:              uchm.TicketSupported,
			sessionTicket:                uchm.SessionTicket,
			supportedSignatureAlgorithms: uchm.SupportedSignatureAlgorithms,
			secureRenegotiation:          uchm.SecureRenegotiation,
			secureRenegotiationSupported: uchm.SecureRenegotiationSupported,
			alpnProtocols:                uchm.AlpnProtocols,

			supportedSignatureAlgorithmsCert: uchm.SupportedSignatureAlgorithmsCert,
			supportedVersions:                uchm.SupportedVersions,
			cookie:                           uchm.Cookie,
			keyShares:                        UKeyShares(uchm.KeyShares).toPrivate(),
			earlyData:                        uchm.EarlyData,
			pskModes:                         uchm.PSKModes,
			pskIdentities:                    UPSKIdentities(uchm.PSKIdentities).toPrivate(),
			pskBinders:                       uchm.PSKBinders,
		}
	}
}

// clientHelloMsg -> UClientHelloMsg
func (chm *clientHelloMsg) toPublic() *UClientHelloMsg {
	if chm == nil {
		return nil
	} else {
		return &UClientHelloMsg{
			Raw:                          chm.raw,
			Vers:                         chm.vers,
			Random:                       chm.random,
			SessionId:                    chm.sessionId,
			CipherSuites:                 chm.cipherSuites,
			CompressionMethods:           chm.compressionMethods,
			NextProtoNeg:                 chm.nextProtoNeg,
			ServerName:                   chm.serverName,
			OcspStapling:                 chm.ocspStapling,
			Scts:                         chm.scts,
			Ems:                          chm.ems,
			SupportedCurves:              chm.supportedCurves,
			SupportedPoints:              chm.supportedPoints,
			TicketSupported:              chm.ticketSupported,
			SessionTicket:                chm.sessionTicket,
			SupportedSignatureAlgorithms: chm.supportedSignatureAlgorithms,
			SecureRenegotiation:          chm.secureRenegotiation,
			SecureRenegotiationSupported: chm.secureRenegotiationSupported,
			AlpnProtocols:                chm.alpnProtocols,

			SupportedSignatureAlgorithmsCert: chm.supportedSignatureAlgorithmsCert,
			SupportedVersions:                chm.supportedVersions,
			Cookie:                           chm.cookie,
			KeyShares:                        keyShares(chm.keyShares).toPublic(),
			EarlyData:                        chm.earlyData,
			PSKModes:                         chm.pskModes,
			PSKIdentities:                    pskIdentities(chm.pskIdentities).toPublic(),
			PSKBinders:                       chm.pskBinders,
		}
	}
}

// UnmarshalClientHello allows external code to parse raw client hellos.
// It returns nil on failure.
func UnmarshalClientHello(data []byte) *UClientHelloMsg {
	m := &clientHelloMsg{}
	if m.unmarshal(data) {
		return m.toPublic()
	}
	return nil
}

// Marshal allows external code to convert a ClientHello object back into
// raw bytes.
func (chm *UClientHelloMsg) Marshal() []byte {
	return chm.toPrivate().marshal()
}

type UServerHelloMsg struct {
	Raw                          []byte
	Vers                         uint16
	Random                       []byte
	SessionId                    []byte
	CipherSuite                  uint16
	CompressionMethod            uint8
	OcspStapling                 bool
	TicketSupported              bool
	SecureRenegotiationSupported bool
	SecureRenegotiation          []byte
	AlpnProtocol                 string
	Ems                          bool
	Scts                         [][]byte
	SupportedVersion             uint16
	ServerShare                  UKeyShare
	SelectedIdentityPresent      bool
	SelectedIdentity             uint16

	// HelloRetryRequest extensions
	Cookie        []byte
	SelectedGroup CurveID

	// [uTLS]
	NextProtoNeg bool
	NextProtos   []string
}

// UServerHelloMsg -> serverHelloMsg
func (ushm *UServerHelloMsg) toPrivate() *serverHelloMsg {
	if ushm == nil {
		return nil
	} else {
		return &serverHelloMsg{
			raw:                          ushm.Raw,
			vers:                         ushm.Vers,
			random:                       ushm.Random,
			sessionId:                    ushm.SessionId,
			cipherSuite:                  ushm.CipherSuite,
			compressionMethod:            ushm.CompressionMethod,
			nextProtoNeg:                 ushm.NextProtoNeg,
			nextProtos:                   ushm.NextProtos,
			ocspStapling:                 ushm.OcspStapling,
			scts:                         ushm.Scts,
			ems:                          ushm.Ems,
			ticketSupported:              ushm.TicketSupported,
			secureRenegotiation:          ushm.SecureRenegotiation,
			secureRenegotiationSupported: ushm.SecureRenegotiationSupported,
			alpnProtocol:                 ushm.AlpnProtocol,
			supportedVersion:             ushm.SupportedVersion,
			serverShare:                  ushm.ServerShare.toPrivate().toObj(),
			selectedIdentityPresent:      ushm.SelectedIdentityPresent,
			selectedIdentity:             ushm.SelectedIdentity,
			cookie:                       ushm.Cookie,
			selectedGroup:                ushm.SelectedGroup,
		}
	}
}

// serverHelloMsg -> UServerHelloMsg
func (shm *serverHelloMsg) toPublic() *UServerHelloMsg {
	if shm == nil {
		return nil
	} else {
		return &UServerHelloMsg{
			Raw:                          shm.raw,
			Vers:                         shm.vers,
			Random:                       shm.random,
			SessionId:                    shm.sessionId,
			CipherSuite:                  shm.cipherSuite,
			CompressionMethod:            shm.compressionMethod,
			NextProtoNeg:                 shm.nextProtoNeg,
			NextProtos:                   shm.nextProtos,
			OcspStapling:                 shm.ocspStapling,
			Scts:                         shm.scts,
			Ems:                          shm.ems,
			TicketSupported:              shm.ticketSupported,
			SecureRenegotiation:          shm.secureRenegotiation,
			SecureRenegotiationSupported: shm.secureRenegotiationSupported,
			AlpnProtocol:                 shm.alpnProtocol,
			SupportedVersion:             shm.supportedVersion,
			ServerShare:                  shm.serverShare.toPublic().toObj(),
			SelectedIdentityPresent:      shm.selectedIdentityPresent,
			SelectedIdentity:             shm.selectedIdentity,
			Cookie:                       shm.cookie,
			SelectedGroup:                shm.selectedGroup,
		}
	}
}

type UCertificateRequestMsgTLS13 struct {
	Raw                              []byte
	OcspStapling                     bool
	Scts                             bool
	SupportedSignatureAlgorithms     []SignatureScheme
	SupportedSignatureAlgorithmsCert []SignatureScheme
	CertificateAuthorities           [][]byte
}

func (crm *certificateRequestMsgTLS13) toPublic() *UCertificateRequestMsgTLS13 {
	if crm == nil {
		return nil
	} else {
		return &UCertificateRequestMsgTLS13{
			Raw:                              crm.raw,
			OcspStapling:                     crm.ocspStapling,
			Scts:                             crm.scts,
			SupportedSignatureAlgorithms:     crm.supportedSignatureAlgorithms,
			SupportedSignatureAlgorithmsCert: crm.supportedSignatureAlgorithmsCert,
			CertificateAuthorities:           crm.certificateAuthorities,
		}
	}
}

func (ucrm *UCertificateRequestMsgTLS13) toPrivate() *certificateRequestMsgTLS13 {
	if ucrm == nil {
		return nil
	} else {
		return &certificateRequestMsgTLS13{
			raw:                              ucrm.Raw,
			ocspStapling:                     ucrm.OcspStapling,
			scts:                             ucrm.Scts,
			supportedSignatureAlgorithms:     ucrm.SupportedSignatureAlgorithms,
			supportedSignatureAlgorithmsCert: ucrm.SupportedSignatureAlgorithmsCert,
			certificateAuthorities:           ucrm.CertificateAuthorities,
		}
	}
}

// Only implemented client-side, for server certificates.
// Alternate certificate message formats (https://datatracker.ietf.org/doc/html/rfc7250) are not
// supported.
// https://datatracker.ietf.org/doc/html/rfc8879
type compressedCertificateMsg struct {
	raw []byte

	algorithm                    uint16
	uncompressedLength           uint32 // uint24
	compressedCertificateMessage []byte
}

func (m *compressedCertificateMsg) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCompressedCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.algorithm)
		b.AddUint24(m.uncompressedLength)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(m.compressedCertificateMessage)
		})
	})

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *compressedCertificateMsg) unmarshal(data []byte) bool {
	*m = compressedCertificateMsg{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.algorithm) ||
		!s.ReadUint24(&m.uncompressedLength) ||
		!readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}
	return true
}
