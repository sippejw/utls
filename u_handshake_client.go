// Copyright 2022 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"hash"
)

// TLS 1.2 and before only
type TLS12OnlyState struct {
	Suite        UCipherSuite
	FinishedHash UFinishedHash
}

// TLS 1.3 only
type TLS13OnlyState struct {
	Suite         *UCipherSuiteTLS13
	ECDHEParams   ECDHEParameters
	EarlySecret   []byte
	BinderKey     []byte
	CertReq       *UCertificateRequestMsgTLS13
	UsingPSK      bool
	SentDummyCCS  bool
	Transcript    hash.Hash
	TrafficSecret []byte // client_application_traffic_secret_0
}

// UClientHandshakeState is an exported crypto/tls.clientHandshakeState
type UClientHandshakeState struct {
	C            *Conn
	Ctx          context.Context
	ServerHello  *UServerHelloMsg
	Hello        *UClientHelloMsg
	MasterSecret []byte
	Session      *ClientSessionState

	State12 TLS12OnlyState
	State13 TLS13OnlyState

	uconn *UConn // [uTLS]
}

// UClientHandshakeState -> clientHandshakeState
func (uchs *UClientHandshakeState) toPrivate12() *clientHandshakeState {
	if uchs == nil {
		return nil
	} else {
		return &clientHandshakeState{
			c:            uchs.C,
			ctx:          uchs.Ctx,
			serverHello:  uchs.ServerHello.toPrivate(),
			hello:        uchs.Hello.toPrivate(),
			suite:        uchs.State12.Suite.toPrivate(),
			finishedHash: uchs.State12.FinishedHash.toPrivate().toObj(),
			masterSecret: uchs.MasterSecret,
			session:      uchs.Session,
			uconn:        uchs.uconn, // [uTLS]
		}
	}
}

// clientHandshakeState -> UClientHandshakeState
func (chs *clientHandshakeState) toPublic() *UClientHandshakeState {
	if chs == nil {
		return nil
	} else {
		return &UClientHandshakeState{
			C:            chs.c,
			Ctx:          chs.ctx,
			ServerHello:  chs.serverHello.toPublic(),
			Hello:        chs.hello.toPublic(),
			MasterSecret: chs.masterSecret,
			Session:      chs.session,
			State12: TLS12OnlyState{
				Suite:        chs.suite.toPublic().toObj(),
				FinishedHash: chs.finishedHash.toPublic().toObj(),
			},
			uconn: chs.uconn,
		}
	}
}

func (uchs13 *UClientHandshakeState) toPrivate13() *clientHandshakeStateTLS13 {
	if uchs13 == nil {
		return nil
	} else {
		return &clientHandshakeStateTLS13{
			c:             uchs13.C,
			ctx:           uchs13.Ctx,
			serverHello:   uchs13.ServerHello.toPrivate(),
			hello:         uchs13.Hello.toPrivate(),
			ecdheParams:   uchs13.State13.ECDHEParams,
			session:       uchs13.Session,
			earlySecret:   uchs13.State13.EarlySecret,
			binderKey:     uchs13.State13.BinderKey,
			certReq:       uchs13.State13.CertReq.toPrivate(),
			usingPSK:      uchs13.State13.UsingPSK,
			sentDummyCCS:  uchs13.State13.SentDummyCCS,
			suite:         uchs13.State13.Suite.toPrivate(),
			transcript:    uchs13.State13.Transcript,
			masterSecret:  uchs13.MasterSecret,
			trafficSecret: uchs13.State13.TrafficSecret,
			uconn:         uchs13.uconn,
		}
	}
}

func (chs13 *clientHandshakeStateTLS13) toPublic() *UClientHandshakeState {
	if chs13 == nil {
		return nil
	} else {
		return &UClientHandshakeState{
			C:           chs13.c,
			Ctx:         chs13.ctx,
			ServerHello: chs13.serverHello.toPublic(),
			Hello:       chs13.hello.toPublic(),

			MasterSecret: chs13.masterSecret,
			Session:      chs13.session,

			State13: TLS13OnlyState{
				ECDHEParams:   chs13.ecdheParams,
				EarlySecret:   chs13.earlySecret,
				BinderKey:     chs13.binderKey,
				CertReq:       chs13.certReq.toPublic(),
				UsingPSK:      chs13.usingPSK,
				SentDummyCCS:  chs13.sentDummyCCS,
				Suite:         chs13.suite.toPublic(),
				Transcript:    chs13.transcript,
				TrafficSecret: chs13.trafficSecret,
			},
			uconn: chs13.uconn,
		}
	}
}
