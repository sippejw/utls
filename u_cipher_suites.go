// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"hash"
)

// UCipherSuite is an exported crypto/tls.CipherSuite
type UCipherSuite struct {
	ID uint16
	// the lengths, in bytes, of the key material needed for each component.
	KeyLen int
	MACLen int
	IVLen  int
	KA     func(version uint16) keyAgreement
	// flags is a bitmask of the suite* values, above.
	Flags  int
	Cipher func(key, iv []byte, isRead bool) interface{}
	MAC    func(macKey []byte) hash.Hash
	AEAD   func(key, fixedNonce []byte) aead
}

// UCipherSuite -> cipherSuite
func (ucs *UCipherSuite) toPrivate() *cipherSuite {
	if ucs == nil {
		return nil
	} else {
		return &cipherSuite{
			id:     ucs.ID,
			keyLen: ucs.KeyLen,
			macLen: ucs.MACLen,
			ivLen:  ucs.IVLen,
			ka:     ucs.KA,
			flags:  ucs.Flags,
			cipher: ucs.Cipher,
			mac:    ucs.MAC,
			aead:   ucs.AEAD,
		}
	}
}

func (ucs *UCipherSuite) toObj() UCipherSuite {
	if ucs == nil {
		return UCipherSuite{}
	} else {
		return *ucs
	}
}

// cipherSuite -> UCipherSuite
func (cs *cipherSuite) toPublic() *UCipherSuite {
	if cs == nil {
		return nil
	} else {
		return &UCipherSuite{
			ID:     cs.id,
			KeyLen: cs.keyLen,
			MACLen: cs.macLen,
			IVLen:  cs.ivLen,
			KA:     cs.ka,
			Flags:  cs.flags,
			Cipher: cs.cipher,
			MAC:    cs.mac,
			AEAD:   cs.aead,
		}
	}
}

func (cs *cipherSuite) toObj() cipherSuite {
	if cs == nil {
		return cipherSuite{}
	} else {
		return *cs
	}
}

type UCipherSuiteTLS13 struct {
	ID     uint16
	KeyLen int
	AEAD   func(key, fixedNonce []byte) aead
	Hash   crypto.Hash
}

func (c *cipherSuiteTLS13) toPublic() *UCipherSuiteTLS13 {
	if c == nil {
		return nil
	} else {
		return &UCipherSuiteTLS13{
			ID:     c.id,
			KeyLen: c.keyLen,
			AEAD:   c.aead,
			Hash:   c.hash,
		}
	}
}

func (c *UCipherSuiteTLS13) toPrivate() *cipherSuiteTLS13 {
	if c == nil {
		return nil
	} else {
		return &cipherSuiteTLS13{
			id:     c.ID,
			keyLen: c.KeyLen,
			aead:   c.AEAD,
			hash:   c.Hash,
		}
	}
}
