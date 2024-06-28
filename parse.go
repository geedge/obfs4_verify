package main

import (
	"crypto/hmac"
	"hash"
	"obfs4/obfs4/common/replayfilter"
	"time"

	"strconv"

	"git.torproject.org/pluggable-transports/obfs4.git/common/ntor"
)

type serverHandshake struct {
	keypair        *ntor.Keypair
	nodeID         *ntor.NodeID
	serverIdentity *ntor.Keypair
	epochHour      []byte
	serverAuth     *ntor.Auth

	padLen int
	mac    hash.Hash

	clientRepresentative *ntor.Representative
	clientMark           []byte
}

func (hs *serverHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	// No point in examining the data unless the miminum plausible response has
	// been received.
	if clientMinHandshakeLength > len(resp) {
		return nil, ErrMarkNotFoundYet
	}

	if hs.clientRepresentative == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to ntor)
		hs.clientRepresentative = new(ntor.Representative)
		copy(hs.clientRepresentative.Bytes()[:], resp[0:ntor.RepresentativeLength])

		// Derive the mark.
		hs.mac.Reset()
		hs.mac.Write(hs.clientRepresentative.Bytes()[:])
		hs.clientMark = hs.mac.Sum(nil)[:markLength]
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.clientMark, resp, ntor.RepresentativeLength+clientMinPadLength,
		maxHandshakeLength, true)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return nil, ErrInvalidHandshake
		}
		return nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	macFound := false
	for _, off := range []int64{0, -1, 1} {
		// Allow epoch to be off by up to a hour in either direction.
		epochHour := []byte(strconv.FormatInt(getEpochHour()+int64(off), 10))
		hs.mac.Reset()
		hs.mac.Write(resp[:pos+markLength])
		hs.mac.Write(epochHour)
		macCmp := hs.mac.Sum(nil)[:macLength]
		macRx := resp[pos+markLength : pos+markLength+macLength]
		if hmac.Equal(macCmp, macRx) {
			// Ensure that this handshake has not been seen previously.
			if filter.TestAndSet(time.Now(), macRx) {
				// The client either happened to generate exactly the same
				// session key and padding, or someone is replaying a previous
				// handshake.  In either case, fuck them.
				return nil, ErrReplayedHandshake
			}

			macFound = true
			hs.epochHour = epochHour

			// We could break out here, but in the name of reducing timing
			// variation, evaluate all 3 MACs.
		}
	}
	if !macFound {
		// This probably should be an InvalidMacError, but conveying the 3 MACS
		// that would be accepted is annoying so just return a generic fatal
		// failure.
		return nil, ErrInvalidHandshake
	}

	// Client should never sent trailing garbage.
	if len(resp) != pos+markLength+macLength {
		return nil, ErrInvalidHandshake
	}

	clientPublic := hs.clientRepresentative.ToPublic()
	ok, seed, auth := ntor.ServerHandshake(clientPublic, hs.keypair,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return nil, ErrNtorFailed
	}
	hs.serverAuth = auth

	return seed.Bytes()[:], nil
}
