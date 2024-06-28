package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net"
	"time"

	"git.torproject.org/pluggable-transports/obfs4.git/common/csrand"

	"strconv"

	"git.torproject.org/pluggable-transports/obfs4.git/common/probdist"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4/framing"

	"git.torproject.org/pluggable-transports/obfs4.git/common/drbg"
	"git.torproject.org/pluggable-transports/obfs4.git/common/ntor"
	"golang.org/x/net/proxy"
)

const (
	iatNone = iota
	iatEnabled
	iatParanoid
	certSuffix      = "=="
	certLength      = ntor.NodeIDLength + ntor.PublicKeyLength
	maxIATDelay     = 100
	consumeReadSize = framing.MaximumSegmentLength * 16

	packetOverhead          = 2 + 1
	seedLength              = drbg.SeedLength
	seedPacketPayloadLength = seedLength
	maxHandshakeLength      = 8192

	clientMinPadLength = (serverMinHandshakeLength + inlineSeedFrameLength) -
		clientMinHandshakeLength
	clientMaxPadLength       = maxHandshakeLength - clientMinHandshakeLength
	clientMinHandshakeLength = ntor.RepresentativeLength + markLength + macLength

	serverMinPadLength = 0
	serverMaxPadLength = maxHandshakeLength - (serverMinHandshakeLength +
		inlineSeedFrameLength)
	serverMinHandshakeLength = ntor.RepresentativeLength + ntor.AuthLength +
		markLength + macLength

	markLength = sha256.Size / 2
	macLength  = sha256.Size / 2

	inlineSeedFrameLength = framing.FrameOverhead + packetOverhead + seedPacketPayloadLength
)

type obfs4ServerCert struct {
	raw []byte
}

type obfs4Conn struct {
	net.Conn

	isServer bool

	lenDist *probdist.WeightedDist
	iatDist *probdist.WeightedDist
	iatMode int

	receiveBuffer        *bytes.Buffer
	receiveDecodedBuffer *bytes.Buffer
	readBuffer           []byte

	encoder *framing.Encoder
	decoder *framing.Decoder
}

type clientHandshake struct {
	keypair        *ntor.Keypair
	nodeID         *ntor.NodeID
	serverIdentity *ntor.PublicKey
	epochHour      []byte

	padLen int
	mac    hash.Hash

	serverRepresentative *ntor.Representative
	serverAuth           *ntor.Auth
	serverMark           []byte
}

// ErrMarkNotFoundYet is the error returned when the obfs4 handshake is
// incomplete and requires more data to continue.  This error is non-fatal and
// is the equivalent to EAGAIN/EWOULDBLOCK.
var ErrMarkNotFoundYet = errors.New("handshake: M_[C,S] not found yet")

// ErrInvalidHandshake is the error returned when the obfs4 handshake fails due
// to the peer not sending the correct mark.  This error is fatal and the
// connection MUST be dropped.
var ErrInvalidHandshake = errors.New("handshake: Failed to find M_[C,S]")

// ErrReplayedHandshake is the error returned when the obfs4 handshake fails
// due it being replayed.  This error is fatal and the connection MUST be
// dropped.
var ErrReplayedHandshake = errors.New("handshake: Replay detected")

// ErrNtorFailed is the error returned when the ntor handshake fails.  This
// error is fatal and the connection MUST be dropped.
var ErrNtorFailed = errors.New("handshake: ntor handshake failure")

// InvalidMacError is the error returned when the handshake MACs do not match.
// This error is fatal and the connection MUST be dropped.
type InvalidMacError struct {
	Derived  []byte
	Received []byte
}

func (e *InvalidMacError) Error() string {
	return fmt.Sprintf("handshake: MAC mismatch: Dervied: %s Received: %s.",
		hex.EncodeToString(e.Derived), hex.EncodeToString(e.Received))
}

// InvalidAuthError is the error returned when the ntor AUTH tags do not match.
// This error is fatal and the connection MUST be dropped.
type InvalidAuthError struct {
	Derived  *ntor.Auth
	Received *ntor.Auth
}

func (e *InvalidAuthError) Error() string {
	return fmt.Sprintf("handshake: ntor AUTH mismatch: Derived: %s Received:%s.",
		hex.EncodeToString(e.Derived.Bytes()[:]),
		hex.EncodeToString(e.Received.Bytes()[:]))
}

func serverCertFromString(encoded string) (*obfs4ServerCert, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded + certSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %s", err)
	}

	if len(decoded) != certLength {
		return nil, fmt.Errorf("cert length %d is invalid", len(decoded))
	}
	//	fmt.Println(decoded)

	return &obfs4ServerCert{raw: decoded}, nil
}

func (cert *obfs4ServerCert) unpack() (*ntor.NodeID, *ntor.PublicKey) {
	if len(cert.raw) != certLength {
		panic(fmt.Sprintf("cert length %d is invalid", len(cert.raw)))
	}

	nodeID, _ := ntor.NewNodeID(cert.raw[:ntor.NodeIDLength])
	pubKey, _ := ntor.NewPublicKey(cert.raw[ntor.NodeIDLength:])
	//fmt.Println(nodeID)
	return nodeID, pubKey
}

func newClientHandshake(nodeID *ntor.NodeID, serverIdentity *ntor.PublicKey, sessionKey *ntor.Keypair) *clientHandshake {
	hs := new(clientHandshake)
	hs.keypair = sessionKey
	hs.nodeID = nodeID
	hs.serverIdentity = serverIdentity
	hs.padLen = csrand.IntRange(clientMinPadLength, clientMaxPadLength)
	hs.mac = hmac.New(sha256.New, append(hs.serverIdentity.Bytes()[:], hs.nodeID.Bytes()[:]...))

	return hs
}

func makePad(padLen int) ([]byte, error) {
	pad := make([]byte, padLen)
	if err := csrand.Bytes(pad); err != nil {
		return nil, err
	}

	return pad, nil
}

func getEpochHour() int64 {
	return time.Now().Unix() / 3600
}

func (hs *clientHandshake) generateHandshake() ([]byte, error) {
	var buf bytes.Buffer

	hs.mac.Reset()
	hs.mac.Write(hs.keypair.Representative().Bytes()[:])
	mark := hs.mac.Sum(nil)[:markLength]

	// The client handshake is X | P_C | M_C | MAC(X | P_C | M_C | E) where:
	//  * X is the client's ephemeral Curve25519 public key representative.
	//  * P_C is [clientMinPadLength,clientMaxPadLength] bytes of random padding.
	//  * M_C is HMAC-SHA256-128(serverIdentity | NodeID, X)
	//  * MAC is HMAC-SHA256-128(serverIdentity | NodeID, X .... E)
	//  * E is the string representation of the number of hours since the UNIX
	//    epoch.

	// Generate the padding
	pad, err := makePad(hs.padLen)
	if err != nil {
		return nil, err
	}

	// Write X, P_C, M_C.
	buf.Write(hs.keypair.Representative().Bytes()[:])
	buf.Write(pad)
	buf.Write(mark)

	// Calculate and write the MAC.
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	hs.mac.Write(hs.epochHour)
	buf.Write(hs.mac.Sum(nil)[:macLength])

	return buf.Bytes(), nil
}

func findMarkMac(mark, buf []byte, startPos, maxPos int, fromTail bool) (pos int) {
	if len(mark) != markLength {
		panic(fmt.Sprintf("BUG: Invalid mark length: %d", len(mark)))
	}

	endPos := len(buf)
	if startPos > len(buf) {
		return -1
	}
	if endPos > maxPos {
		endPos = maxPos
	}
	if endPos-startPos < markLength+macLength {
		return -1
	}

	if fromTail {
		// The server can optimize the search process by only examining the
		// tail of the buffer.  The client can't send valid data past M_C |
		// MAC_C as it does not have the server's public key yet.
		pos = endPos - (markLength + macLength)
		if !hmac.Equal(buf[pos:pos+markLength], mark) {
			return -1
		}

		return
	}

	// The client has to actually do a substring search since the server can
	// and will send payload trailing the response.
	//
	// XXX: bytes.Index() uses a naive search, which kind of sucks.
	pos = bytes.Index(buf[startPos:endPos], mark)
	if pos == -1 {
		return -1
	}

	// Ensure that there is enough trailing data for the MAC.
	if startPos+pos+markLength+macLength > endPos {
		return -1
	}

	// Return the index relative to the start of the slice.
	pos += startPos
	return
}

func (hs *clientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	// No point in examining the data unless the miminum plausible response has
	// been received.
	if serverMinHandshakeLength > len(resp) {
		return 0, nil, ErrMarkNotFoundYet
	}

	if hs.serverRepresentative == nil || hs.serverAuth == nil {
		// Pull out the representative/AUTH. (XXX: Add ctors to ntor)
		hs.serverRepresentative = new(ntor.Representative)
		copy(hs.serverRepresentative.Bytes()[:], resp[0:ntor.RepresentativeLength])
		hs.serverAuth = new(ntor.Auth)
		copy(hs.serverAuth.Bytes()[:], resp[ntor.RepresentativeLength:])

		// Derive the mark.
		hs.mac.Reset()
		hs.mac.Write(hs.serverRepresentative.Bytes()[:])
		hs.serverMark = hs.mac.Sum(nil)[:markLength]
	}

	// Attempt to find the mark + MAC.
	pos := findMarkMac(hs.serverMark, resp, ntor.RepresentativeLength+ntor.AuthLength+serverMinPadLength,
		maxHandshakeLength, false)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return 0, nil, ErrInvalidHandshake
		}
		return 0, nil, ErrMarkNotFoundYet
	}

	// Validate the MAC.
	hs.mac.Reset()
	hs.mac.Write(resp[:pos+markLength])
	hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)[:macLength]
	macRx := resp[pos+markLength : pos+markLength+macLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	// Complete the handshake.
	serverPublic := hs.serverRepresentative.ToPublic()
	ok, seed, auth := ntor.ClientHandshake(hs.keypair, serverPublic,
		hs.serverIdentity, hs.nodeID)
	if !ok {
		return 0, nil, ErrNtorFailed
	}
	if !ntor.CompareAuth(auth, hs.serverAuth.Bytes()[:]) {
		return 0, nil, &InvalidAuthError{auth, hs.serverAuth}
	}

	return pos + markLength + macLength, seed.Bytes()[:], nil
}

func (conn *obfs4Conn) clientHandshake(nodeID *ntor.NodeID, peerIdentityKey *ntor.PublicKey, sessionKey *ntor.Keypair) error {
	if conn.isServer {
		return fmt.Errorf("clientHandshake called on server connection")
	}

	// Generate and send the client handshake.
	hs := newClientHandshake(nodeID, peerIdentityKey, sessionKey)
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	if _, err = conn.Conn.Write(blob); err != nil {
		return err
	}

	// Consume the server handshake.
	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			// The Read() could have returned data and an error, but there is
			// no point in continuing on an EOF or whatever.
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])

		n, _, err = hs.parseServerHandshake(conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = conn.receiveBuffer.Next(n)

		// Use the derived key material to intialize the link crypto.
		//okm := ntor.Kdf(seed, framing.KeyLength*2)
		//conn.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		//conn.decoder = framing.NewDecoder(okm[framing.KeyLength:])

		return nil
	}
}

func verify(ptName string, certStr string, address string, iatStr string) int {
	var nodeID *ntor.NodeID
	var publicKey *ntor.PublicKey
	cert, err := serverCertFromString(certStr)
	if err != nil {
		return -1 //certStrErr
	}
	nodeID, publicKey = cert.unpack()
	iatMode, err := strconv.Atoi(iatStr)
	//fmt.Printf(" iatMode %d \n", iatMode)
	if err != nil || iatMode < iatNone || iatMode > iatParanoid {
		fmt.Printf("invalid iat-mode '%d'\n", iatMode)
		return -2 //iatStrErr
	}
	sessionKey, err := ntor.NewKeypair(true)
	if err != nil {
		return -3 //sessionkeyErr
	}

	dialFn := proxy.Direct.Dial
	remote, err := dialFn("tcp", address)
	if err != nil {
		return -4 //dialErr
	}
	defer remote.Close()
	//newObfs4ClientConn
	//var seed *drbg.Seed
	//if seed, err = drbg.NewSeed(); err != nil {
	//	return -5 //newseedErr
	//}
	//var biasedDist bool // default to be false
	//lenDist := probdist.New(seed, 0, framing.MaximumSegmentLength, biasedDist)
	var lenDist *probdist.WeightedDist
	var iatDist *probdist.WeightedDist
	//if iatMode != iatNone {
	//	var iatSeed *drbg.Seed
	//	iatSeedSrc := sha256.Sum256(seed.Bytes()[:])
	//	if iatSeed, err = drbg.SeedFromBytes(iatSeedSrc[:]); err != nil {
	//		return -6 //seedErr
	//	}
	//	iatDist = probdist.New(iatSeed, 0, maxIATDelay, biasedDist)
	//}
	// Allocate the client structure.
	c := &obfs4Conn{remote, false, lenDist, iatDist, iatMode, bytes.NewBuffer(nil), bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	if err = c.clientHandshake(nodeID, publicKey, sessionKey); err != nil {
		return -7 //clienthsErr
	}

	return 1

}

func main() {
	var ptName string
	ptName = "obfs4"
	var certStr string
	certStr = "iJ8il3a2gVXuNdZoaPwQ0QgdOJyBAi4fcY642f6sTErVNZ14Ax7c9w9qa36mUXQhbm9vOg"
	//	certStr = "M6tiPcFv8YK2jE8pYZb9AKMMHHag4OrhHFWmOXHR+J9s8Ty9X9V+Bn0emEZmfnqhdtHkdA"
	var iatStr string
	iatStr = "0"
	var address string
	address = "185.185.251.132:443"
	//	address = "45.32.201.89:51433"
	var result int
	result = verify(ptName, certStr, address, iatStr)
	fmt.Println(result)
}
