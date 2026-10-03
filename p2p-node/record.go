package main

// Handle records: the only data the NodeX DHT holds.
//
// Key:   "/nodex/" + handleKey            e.g. "/nodex/rahul#bftrjn"
// Value: JSON {v, handle, peer_id, email_commitment, seq, sig}
//
// A record is accepted only if
//   - it is stored under the key of its own handle (case-insensitive),
//   - it is signed by the Ed25519 key embedded in its Peer ID, and
//   - the handle's tag re-derives from (name, Peer ID, email commitment)
//     using the same slow PBKDF2 as the browser — so nobody can publish a
//     record for a handle that isn't theirs.
//
// Must stay byte-for-byte compatible with lib/p2p/record.ts in the NodeX-frontend repository.

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
)

const (
	recordNamespace  = "nodex"
	keyPrefix        = "/" + recordNamespace + "/"
	maxRecordBytes   = 2048
	tagIterations    = 600_000
	tagLength        = 6
	tagAlphabet      = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	maxFutureSkew    = 10 * time.Minute
	validationCacheN = 4096
)

var handleRe = regexp.MustCompile(`^([A-Za-z0-9_]{2,20})#([0-9A-Za-z]{6})$`)

// HandleRecord is the signed JSON value stored in the DHT.
type HandleRecord struct {
	Version         int    `json:"v"`
	Handle          string `json:"handle"`
	PeerID          string `json:"peer_id"`
	EmailCommitment string `json:"email_commitment"`
	Seq             int64  `json:"seq"`
	Sig             string `json:"sig"`
}

// signedMessage is what the owner signs.
func signedMessage(handleKey, peerID, commitment string, seq int64) []byte {
	return fmt.Appendf(nil, "nodex-handle-record-v1\n%s\n%s\n%s\n%d", handleKey, peerID, commitment, seq)
}

type parsedHandle struct{ name, tag, key string }

// parseHandle mirrors lib/handle.ts: case-insensitive, Crockford look-alikes.
func parseHandle(s string) (parsedHandle, bool) {
	m := handleRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return parsedHandle{}, false
	}
	tag := strings.NewReplacer("I", "1", "L", "1", "O", "0").Replace(strings.ToUpper(m[2]))
	for _, c := range tag {
		if !strings.ContainsRune(tagAlphabet, c) {
			return parsedHandle{}, false
		}
	}
	return parsedHandle{name: m[1], tag: tag, key: strings.ToLower(m[1] + "#" + tag)}, true
}

// handleTag mirrors handleTag() in lib/identity.ts.
func handleTag(name, peerID string, commitment []byte) (string, error) {
	salt := append([]byte(peerID), commitment...)
	digest, err := pbkdf2.Key(sha256.New, "nodex-handle-v1|"+strings.ToLower(name), salt, tagIterations, 32)
	if err != nil {
		return "", err
	}
	// Same bit extraction as the browser (int32 arithmetic there; only the
	// low bits are ever read, so uint32 wrap-around gives identical results).
	var value uint32
	bits := 0
	var tag strings.Builder
	for _, b := range digest {
		value = value<<8 | uint32(b)
		bits += 8
		for bits >= 5 && tag.Len() < tagLength {
			tag.WriteByte(tagAlphabet[(value>>(bits-5))&31])
			bits -= 5
		}
		if tag.Len() == tagLength {
			break
		}
	}
	return tag.String(), nil
}

// Validator implements record.Validator for the "nodex" namespace.
type Validator struct {
	now func() time.Time

	mu    sync.Mutex
	cache map[[32]byte]error // value hash → result; PBKDF2 is deliberately slow
}

func NewValidator() *Validator {
	return &Validator{now: time.Now, cache: map[[32]byte]error{}}
}

func (v *Validator) Validate(key string, value []byte) error {
	cacheKey := sha256.Sum256(append([]byte(key+"\x00"), value...))
	v.mu.Lock()
	if err, ok := v.cache[cacheKey]; ok {
		v.mu.Unlock()
		return err
	}
	v.mu.Unlock()

	_, err := v.validate(key, value)

	v.mu.Lock()
	if len(v.cache) >= validationCacheN {
		v.cache = map[[32]byte]error{}
	}
	v.cache[cacheKey] = err
	v.mu.Unlock()
	return err
}

func (v *Validator) validate(key string, value []byte) (*HandleRecord, error) {
	if len(value) > maxRecordBytes {
		return nil, errors.New("record too large")
	}
	var r HandleRecord
	dec := json.NewDecoder(bytes.NewReader(value))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("bad record json: %w", err)
	}
	if r.Version != 1 {
		return nil, errors.New("unsupported record version")
	}

	h, ok := parseHandle(r.Handle)
	if !ok {
		return nil, errors.New("invalid handle")
	}
	if key != keyPrefix+h.key {
		return nil, errors.New("record stored under the wrong key")
	}

	pid, err := peer.Decode(r.PeerID)
	if err != nil {
		return nil, errors.New("invalid peer id")
	}
	pub, err := pid.ExtractPublicKey()
	if err != nil || pub.Type() != pb.KeyType_Ed25519 {
		return nil, errors.New("peer id must embed an Ed25519 key")
	}

	commitment, err := base64.StdEncoding.DecodeString(r.EmailCommitment)
	if err != nil || len(commitment) != 32 {
		return nil, errors.New("invalid email commitment")
	}
	if r.Seq <= 0 || time.UnixMilli(r.Seq).After(v.now().Add(maxFutureSkew)) {
		return nil, errors.New("invalid sequence number")
	}

	sig, err := base64.StdEncoding.DecodeString(r.Sig)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}
	if ok, err := pub.Verify(signedMessage(h.key, r.PeerID, r.EmailCommitment, r.Seq), sig); err != nil || !ok {
		return nil, errors.New("bad signature")
	}

	tag, err := handleTag(h.name, r.PeerID, commitment)
	if err != nil {
		return nil, err
	}
	if tag != h.tag {
		return nil, errors.New("handle is not bound to this peer id")
	}
	return &r, nil
}

// Select picks the newest valid record (highest seq). Owners republish
// regularly, so the newest record reflects the owner's current state.
func (v *Validator) Select(key string, values [][]byte) (int, error) {
	best, bestSeq := -1, int64(-1)
	for i, val := range values {
		if v.Validate(key, val) != nil {
			continue
		}
		var r HandleRecord
		if json.Unmarshal(val, &r) != nil {
			continue
		}
		if r.Seq > bestSeq {
			best, bestSeq = i, r.Seq
		}
	}
	if best < 0 {
		return 0, errors.New("no valid record")
	}
	return best, nil
}
