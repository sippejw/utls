// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import "hash"

// A UFinishedHash is an exported crypto/tls.finishedHash
type UFinishedHash struct {
	Client hash.Hash
	Server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	ClientMD5 hash.Hash
	ServerMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	Buffer []byte

	Version uint16
	Prf     func(result, secret, label, seed []byte)
}

// UFinishedHash -> finishedHash
func (ufh *UFinishedHash) toPrivate() *finishedHash {
	if ufh == nil {
		return nil
	} else {
		return &finishedHash{
			client:    ufh.Client,
			server:    ufh.Server,
			clientMD5: ufh.ClientMD5,
			serverMD5: ufh.ServerMD5,
			buffer:    ufh.Buffer,
			version:   ufh.Version,
			prf:       ufh.Prf,
		}
	}
}

func (ufh *UFinishedHash) toObj() UFinishedHash {
	if ufh == nil {
		return UFinishedHash{}
	} else {
		return *ufh
	}
}

func (fh *finishedHash) toPublic() *UFinishedHash {
	if fh == nil {
		return nil
	} else {
		return &UFinishedHash{
			Client:    fh.client,
			Server:    fh.server,
			ClientMD5: fh.clientMD5,
			ServerMD5: fh.serverMD5,
			Buffer:    fh.buffer,
			Version:   fh.version,
			Prf:       fh.prf}
	}
}

func (fh *finishedHash) toObj() finishedHash {
	if fh == nil {
		return finishedHash{}
	} else {
		return *fh
	}
}
