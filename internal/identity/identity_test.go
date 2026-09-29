package identity

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

func newIdentity(t *testing.T) (crypto.PrivKey, []byte, string) {
	t.Helper()
	priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := crypto.MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pubBytes, id.String()
}

func TestVerify(t *testing.T) {
	priv, pub, id := newIdentity(t)
	msg := RegistrationMessage("Rahul", id, "tok")
	sig, err := priv.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}

	if err := Verify(pub, id, msg, sig); err != nil {
		t.Fatalf("valid identity rejected: %v", err)
	}

	_, otherPub, otherID := newIdentity(t)
	cases := map[string]struct {
		pub  []byte
		id   string
		msg  []byte
		want error
	}{
		"garbage key":         {[]byte("nope"), id, msg, ErrInvalidPublicKey},
		"bad peer id":         {pub, "not-a-peer-id", msg, ErrInvalidPeerID},
		"peer id mismatch":    {pub, otherID, msg, ErrPeerIDMismatch},
		"key of other peer":   {otherPub, id, msg, ErrPeerIDMismatch},
		"tampered username":   {pub, id, RegistrationMessage("Mallory", id, "tok"), ErrInvalidSignature},
		"replayed to session": {pub, id, RegistrationMessage("Rahul", id, "other"), ErrInvalidSignature},
	}
	for name, c := range cases {
		if err := Verify(c.pub, c.id, c.msg, sig); err != c.want {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}
