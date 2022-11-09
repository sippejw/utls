// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
)

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.
const (
	utlsExtensionPadding              uint16 = 21
	utlsExtensionExtendedMasterSecret uint16 = 23 // https://tools.ietf.org/html/rfc7627

	// https://datatracker.ietf.org/doc/html/rfc8879#section-7.1
	utlsExtensionCompressCertificate uint16 = 27

	// extensions with 'fake' prefix break connection, if server echoes them back
	fakeExtensionTokenBinding         uint16 = 24
	fakeExtensionChannelIDOld         uint16 = 30031 // not IANA assigned
	fakeExtensionChannelID            uint16 = 30032 // not IANA assigned
	fakeExtensionALPS                 uint16 = 17513 // not IANA assigned
	fakeExtensionDelegatedCredentials uint16 = 34

	fakeRecordSizeLimit uint16 = 0x001c

	// https://datatracker.ietf.org/doc/html/rfc8879#section-7.2
	typeCompressedCertificate uint8 = 25
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = uint16(0x0032)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = uint16(0x006b)
	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = uint16(0x0067)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)

	// https://docs.microsoft.com/en-us/dotnet/api/system.net.security.tlsciphersuite?view=netcore-3.1
	FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = uint16(0xc008)
)

// newest signatures
var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303

	FakeSHA1WithDSA   SignatureScheme = 0x0202
	FakeSHA256WithDSA SignatureScheme = 0x0402

	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// fake curves(groups)
var (
	FakeFFDHE2048 = uint16(0x0100)
	FakeFFDHE3072 = uint16(0x0101)
)

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type UKeyShare struct {
	Group CurveID
	Data  []byte
}

// UKeyShare -> keyShare
func (uks *UKeyShare) toPrivate() *keyShare {
	if uks == nil {
		return nil
	} else {
		return &keyShare{
			group: uks.Group,
			data:  uks.Data,
		}
	}
}

// *UKeyShare -> UKeyShare
func (uks *UKeyShare) toObj() UKeyShare {
	if uks == nil {
		return UKeyShare{}
	} else {
		return *uks
	}
}

// keyShare -> UKeyShare
func (ks *keyShare) toPublic() *UKeyShare {
	if ks == nil {
		return nil
	} else {
		return &UKeyShare{
			Group: ks.group,
			Data:  ks.data,
		}
	}
}

// *keyShare -> keyShare
func (ks *keyShare) toObj() keyShare {
	if ks == nil {
		return keyShare{}
	} else {
		return *ks
	}
}

type UKeyShares []UKeyShare
type keyShares []keyShare

// UKeyShares([]UKeyShare) -> keyShares([]keyShare)
func (ukss UKeyShares) toPrivate() []keyShare {
	var kss []keyShare
	for _, ks := range ukss {
		kss = append(kss, keyShare{data: ks.Data, group: ks.Group})
	}
	return kss
}

// keyShares([]keyShare) -> UKeyShares([]UKeyShare)
func (kss keyShares) toPublic() []UKeyShare {
	var KSS []UKeyShare
	for _, ks := range kss {
		KSS = append(KSS, UKeyShare{Data: ks.data, Group: ks.group})
	}
	return KSS
}

type UPSKIdentity struct {
	Label               []byte
	ObfuscatedTicketAge uint32
}

type UPSKIdentities []UPSKIdentity
type pskIdentities []pskIdentity

// UPSKIdentities([]UPSKIdentity) -> pskIdentities([]pskIdentity)
func (upids UPSKIdentities) toPrivate() []pskIdentity {
	var pids []pskIdentity
	for _, pid := range upids {
		pids = append(pids, pskIdentity{label: pid.Label, obfuscatedTicketAge: pid.ObfuscatedTicketAge})
	}
	return pids
}

// pskIdentities([]pskIdentity) -> UPSKIdentities([]UPSKIdentity)
func (pids pskIdentities) toPublic() []UPSKIdentity {
	var upids []UPSKIdentity
	for _, pid := range pids {
		upids = append(upids, UPSKIdentity{Label: pid.label, ObfuscatedTicketAge: pid.obfuscatedTicketAge})
	}
	return upids
}

// ClientSessionState is public, but all its fields are private. Let's add setters, getters and constructor

// ClientSessionState contains the state needed by clients to resume TLS sessions.
func MakeClientSessionState(
	SessionTicket []uint8,
	Vers uint16,
	CipherSuite uint16,
	MasterSecret []byte,
	ServerCertificates []*x509.Certificate,
	VerifiedChains [][]*x509.Certificate) *ClientSessionState {
	css := ClientSessionState{sessionTicket: SessionTicket,
		vers:               Vers,
		cipherSuite:        CipherSuite,
		masterSecret:       MasterSecret,
		serverCertificates: ServerCertificates,
		verifiedChains:     VerifiedChains}
	return &css
}

// Encrypted ticket used for session resumption with server
func (css *ClientSessionState) SessionTicket() []uint8 {
	return css.sessionTicket
}

// SSL/TLS version negotiated for the session
func (css *ClientSessionState) Vers() uint16 {
	return css.vers
}

// Ciphersuite negotiated for the session
func (css *ClientSessionState) CipherSuite() uint16 {
	return css.cipherSuite
}

// MasterSecret generated by client on a full handshake
func (css *ClientSessionState) MasterSecret() []byte {
	return css.masterSecret
}

// Certificate chain presented by the server
func (css *ClientSessionState) ServerCertificates() []*x509.Certificate {
	return css.serverCertificates
}

// Certificate chains we built for verification
func (css *ClientSessionState) VerifiedChains() [][]*x509.Certificate {
	return css.verifiedChains
}

func (css *ClientSessionState) SetSessionTicket(SessionTicket []uint8) {
	css.sessionTicket = SessionTicket
}
func (css *ClientSessionState) SetVers(Vers uint16) {
	css.vers = Vers
}
func (css *ClientSessionState) SetCipherSuite(CipherSuite uint16) {
	css.cipherSuite = CipherSuite
}
func (css *ClientSessionState) SetMasterSecret(MasterSecret []byte) {
	css.masterSecret = MasterSecret
}
func (css *ClientSessionState) SetServerCertificates(ServerCertificates []*x509.Certificate) {
	css.serverCertificates = ServerCertificates
}
func (css *ClientSessionState) SetVerifiedChains(VerifiedChains [][]*x509.Certificate) {
	css.verifiedChains = VerifiedChains
}

// TicketKey is the internal representation of a session ticket key.
type TicketKey struct {
	// KeyName is an opaque byte string that serves to identify the session
	// ticket key. It's exposed as plaintext in every session ticket.
	KeyName [ticketKeyNameLen]byte
	AesKey  [16]byte
	HmacKey [16]byte
}

type TicketKeys []TicketKey
type ticketKeys []ticketKey

func TicketKeyFromBytes(b [32]byte) TicketKey {
	// [uTLS]
	// empty config is required
	config := &Config{}
	tk := config.ticketKeyFromBytes(b)
	return tk.toPublic()
}

func (tk ticketKey) toPublic() TicketKey {
	return TicketKey{
		KeyName: tk.keyName,
		AesKey:  tk.aesKey,
		HmacKey: tk.hmacKey,
	}
}

func (TK TicketKey) toPrivate() ticketKey {
	return ticketKey{
		keyName: TK.KeyName,
		aesKey:  TK.AesKey,
		hmacKey: TK.HmacKey,
	}
}

func (tks ticketKeys) toPublic() []TicketKey {
	var TKS []TicketKey
	for _, ks := range tks {
		TKS = append(TKS, ks.toPublic())
	}
	return TKS
}

func (TKS TicketKeys) toPrivate() []ticketKey {
	var tks []ticketKey
	for _, TK := range TKS {
		tks = append(tks, TK.toPrivate())
	}
	return tks
}

// https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 0x0001
	CertCompressionBrotli CertCompressionAlgo = 0x0002
	CertCompressionZstd   CertCompressionAlgo = 0x0003
)

const (
	PskModePlain uint8 = pskModePlain
	PskModeDHE   uint8 = pskModeDHE
)

type ClientHelloID struct {
	Client string

	// Version specifies version of a mimicked clients (e.g. browsers).
	// Not used in randomized, custom handshake, and default Go.
	Version string

	// Seed is only used for randomized fingerprints to seed PRNG.
	// Must not be modified once set.
	Seed *PRNGSeed
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", p.Client, p.Version)
}

func (p *ClientHelloID) IsSet() bool {
	return (p.Client == "") && (p.Version == "")
}

const (
	// clients
	helloGolang           = "Golang"
	helloRandomized       = "Randomized"
	helloRandomizedALPN   = "Randomized-ALPN"
	helloRandomizedNoALPN = "Randomized-NoALPN"
	helloCustom           = "Custom"
	helloFirefox          = "Firefox"
	helloChrome           = "Chrome"
	helloIOS              = "iOS"
	helloAndroid          = "Android"
	helloEdge             = "Edge"
	helloSafari           = "Safari"
	hello360              = "360Browser"
	helloQQ               = "QQBrowser"

	// versions
	helloAutoVers = "0"
)

type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions

	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = ClientHelloID{helloGolang, helloAutoVers, nil}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = ClientHelloID{helloCustom, helloAutoVers, nil}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = ClientHelloID{helloRandomized, helloAutoVers, nil}
	HelloRandomizedALPN   = ClientHelloID{helloRandomizedALPN, helloAutoVers, nil}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomizedNoALPN, helloAutoVers, nil}

	// The rest will will parrot given browser.
	HelloFirefox_Auto = HelloFirefox_105
	HelloFirefox_55   = ClientHelloID{helloFirefox, "55", nil}
	HelloFirefox_56   = ClientHelloID{helloFirefox, "56", nil}
	HelloFirefox_63   = ClientHelloID{helloFirefox, "63", nil}
	HelloFirefox_65   = ClientHelloID{helloFirefox, "65", nil}
	HelloFirefox_99   = ClientHelloID{helloFirefox, "99", nil}
	HelloFirefox_102  = ClientHelloID{helloFirefox, "102", nil}
	HelloFirefox_105  = ClientHelloID{helloFirefox, "105", nil}

	HelloChrome_Auto = HelloChrome_102
	HelloChrome_58   = ClientHelloID{helloChrome, "58", nil}
	HelloChrome_62   = ClientHelloID{helloChrome, "62", nil}
	HelloChrome_70   = ClientHelloID{helloChrome, "70", nil}
	HelloChrome_72   = ClientHelloID{helloChrome, "72", nil}
	HelloChrome_83   = ClientHelloID{helloChrome, "83", nil}
	HelloChrome_87   = ClientHelloID{helloChrome, "87", nil}
	HelloChrome_96   = ClientHelloID{helloChrome, "96", nil}
	HelloChrome_100  = ClientHelloID{helloChrome, "100", nil}
	HelloChrome_102  = ClientHelloID{helloChrome, "102", nil}

	HelloIOS_Auto = HelloIOS_14
	HelloIOS_11_1 = ClientHelloID{helloIOS, "111", nil} // legacy "111" means 11.1
	HelloIOS_12_1 = ClientHelloID{helloIOS, "12.1", nil}
	HelloIOS_13   = ClientHelloID{helloIOS, "13", nil}
	HelloIOS_14   = ClientHelloID{helloIOS, "14", nil}

	HelloAndroid_11_OkHttp = ClientHelloID{helloAndroid, "11", nil}

	HelloEdge_Auto = HelloEdge_85 // HelloEdge_106 seems to be incompatible with this library
	HelloEdge_85   = ClientHelloID{helloEdge, "85", nil}
	HelloEdge_106  = ClientHelloID{helloEdge, "106", nil}

	HelloSafari_Auto = HelloSafari_16_0
	HelloSafari_16_0 = ClientHelloID{helloSafari, "16.0", nil}

	Hello360_Auto = Hello360_7_5 // Hello360_11_0 seems to be incompatible with this library
	Hello360_7_5  = ClientHelloID{hello360, "7.5", nil}
	Hello360_11_0 = ClientHelloID{hello360, "11.0", nil}

	HelloQQ_Auto = HelloQQ_11_1
	HelloQQ_11_1 = ClientHelloID{helloQQ, "11.1", nil}
)

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	} else {
		return v
	}
}

// utlsMacSHA384 returns a SHA-384 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func utlsMacSHA384(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	}...)
}

// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
// This provides better compatibility with servers on the web, but weakens security. Feel free
// to use this option if you establish additional secure connection inside of utls connection.
// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
// Must be called before establishing any connections.
func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}
