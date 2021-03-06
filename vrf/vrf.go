// Copyright 2020 Wintex
// SPDX-License-Identifier: LGPL-3.0-only

package vrf

import (
	"encoding/binary"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
	"github.com/gtank/merlin"
)

func VRF(randomness [32]byte, proposal uint64, msk *schnorrkel.MiniSecretKey) (*Uint128, *schnorrkel.VrfInOut, *schnorrkel.VrfProof, error) {
	signTranscript := makeTranscript(randomness, proposal)
	priv := msk.ExpandEd25519()
	pub := msk.Public()

	inout, proof, err := priv.VrfSign(signTranscript)
	if err != nil {
		return nil, nil, nil, err
	}

	inoutt := attachInput(inout.Output().Encode(), pub, signTranscript)
	res := inoutt.MakeBytes(16, []byte("doton-vrf"))
	inoutUint := uint128FromLEBytes(res)

	return inoutUint, inout, proof, err
}

func makeTranscript(randomness [32]byte, proposal uint64) *merlin.Transcript {
	t := merlin.NewTranscript("DOTON")
	appendUint64(t, []byte("proposal number"), proposal)
	t.AppendMessage([]byte("chain randomness"), randomness[:])
	return t
}

func attachInput(output [32]byte, pub *schnorrkel.PublicKey, t *merlin.Transcript) *schnorrkel.VrfInOut {
	out := schnorrkel.NewOutput(output)
	return out.AttachInput(pub, t)
}

func appendUint64(t *merlin.Transcript, label []byte, n uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, n)
	t.AppendMessage(label, buf)
}

type Uint128 struct {
	Upper uint64
	Lower uint64
}

func (u *Uint128) Cmp(other *Uint128) int {
	if u.Upper > other.Upper {
		return 1
	}

	if u.Upper < other.Upper {
		return -1
	}

	if u.Lower > other.Lower {
		return 1
	}

	if u.Lower < other.Lower {
		return -1
	}

	return 0
}

func padTo16BytesLE(in []byte) []byte {
	for len(in) != 16 {
		in = append(in, 0)
	}
	return in
}

func uint128FromLEBytes(in []byte) *Uint128 {
	if len(in) < 16 {
		in = padTo16BytesLE(in)
	}

	lower := binary.LittleEndian.Uint64(in[:8])
	upper := binary.LittleEndian.Uint64(in[8:])

	return &Uint128{
		Upper: upper,
		Lower: lower,
	}
}
