package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

type identity struct {
	priv       crypto.PrivKey
	peerID     string
	commitment string
	handle     string
}

func newIdentity(t *testing.T, name string) identity {
	t.Helper()
	priv, pub, _ := crypto.GenerateEd25519Key(rand.Reader)
	pid, _ := peer.IDFromPublicKey(pub)
	c := make([]byte, 32)
	rand.Read(c)
	tag, err := handleTag(name, pid.String(), c)
	if err != nil {
		t.Fatal(err)
	}
	return identity{priv, pid.String(), base64.StdEncoding.EncodeToString(c), name + "#" + tag}
}

// record builds a signed record; mutate lets tests tamper before signing.
func record(t *testing.T, id identity, seq int64, mutate func(*HandleRecord)) (string, []byte) {
	t.Helper()
	r := HandleRecord{Version: 1, Handle: id.handle, PeerID: id.peerID, EmailCommitment: id.commitment, Seq: seq}
	if mutate != nil {
		mutate(&r)
	}
	h, _ := parseHandle(r.Handle)
	sig, _ := id.priv.Sign(signedMessage(h.key, r.PeerID, r.EmailCommitment, r.Seq))
	r.Sig = base64.StdEncoding.EncodeToString(sig)
	b, _ := json.Marshal(r)
	return keyPrefix + h.key, b
}

func TestValidRecordAndCaseInsensitiveKey(t *testing.T) {
	v := NewValidator()
	id := newIdentity(t, "Rahul")
	key, val := record(t, id, time.Now().UnixMilli(), nil)
	if err := v.Validate(key, val); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if key != strings.ToLower(key) {
		t.Errorf("key must be canonical lowercase: %s", key)
	}
	// A record whose handle is typed in other capitalisation still maps to the same key.
	key2, val2 := record(t, id, time.Now().UnixMilli(), func(r *HandleRecord) { r.Handle = strings.ToUpper(r.Handle) })
	if key2 != key || v.Validate(key2, val2) != nil {
		t.Errorf("upper-case handle should be valid under the same key")
	}
}

func TestRejectsForgeries(t *testing.T) {
	v := NewValidator()
	victim := newIdentity(t, "Rahul")
	attacker := newIdentity(t, "Rahul")
	now := time.Now().UnixMilli()

	vKey, vVal := record(t, victim, now, nil)

	cases := map[string]struct {
		key string
		val []byte
	}{}

	// Attacker claims the victim's handle with their own key (validly signed).
	k, val := record(t, attacker, now, func(r *HandleRecord) { r.Handle = victim.handle })
	cases["handle not bound to signer's peer id"] = struct {
		key string
		val []byte
	}{k, val}

	// Attacker copies the victim's record but points it at their own peer id.
	var r HandleRecord
	json.Unmarshal(vVal, &r)
	r.PeerID = attacker.peerID
	b, _ := json.Marshal(r)
	cases["peer id swapped (bad signature)"] = struct {
		key string
		val []byte
	}{vKey, b}

	// Valid record stored under someone else's key.
	cases["wrong key"] = struct {
		key string
		val []byte
	}{keyPrefix + "other#abcdef", vVal}

	// Future-dated sequence number.
	k, val = record(t, victim, time.Now().Add(time.Hour).UnixMilli(), nil)
	cases["future seq"] = struct {
		key string
		val []byte
	}{k, val}

	// Garbage and oversized values.
	cases["garbage"] = struct {
		key string
		val []byte
	}{vKey, []byte("not json")}
	cases["oversized"] = struct {
		key string
		val []byte
	}{vKey, make([]byte, maxRecordBytes+1)}

	for name, c := range cases {
		if err := v.Validate(c.key, c.val); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSelectNewest(t *testing.T) {
	v := NewValidator()
	id := newIdentity(t, "Asha")
	now := time.Now().UnixMilli()
	key, old := record(t, id, now-1000, nil)
	_, newer := record(t, id, now, nil)
	i, err := v.Select(key, [][]byte{old, []byte("junk"), newer})
	if err != nil || i != 2 {
		t.Fatalf("Select = %d, %v; want 2", i, err)
	}
}

func TestParseHandleLookAlikes(t *testing.T) {
	h, ok := parseHandle("rahul#bftrjo")
	if !ok || h.tag != "BFTRJ0" || h.key != "rahul#bftrj0" {
		t.Fatalf("got %+v %v", h, ok)
	}
	if _, ok := parseHandle("rahul#bftrju"); ok {
		t.Error("U is not in the tag alphabet")
	}
}
