// Package identity verifies the libp2p peer identity a client generated on
// its own device. The backend only ever sees the public half.
package identity

import (
	"errors"
	"fmt"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/crypto/pb"
	"github.com/libp2p/go-libp2p/core/peer"
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrInvalidPeerID    = errors.New("invalid peer id")
	ErrPeerIDMismatch   = errors.New("peer id does not match public key")
	ErrInvalidSignature = errors.New("invalid signature")
)

// RegistrationMessage is the exact payload the client signs to prove it holds
// the private key. The frontend builds the same string byte-for-byte.
func RegistrationMessage(username, peerID, sessionToken string) []byte {
	return fmt.Appendf(nil, "NodeX identity registration v1\nusername:%s\npeer_id:%s\nsession:%s", username, peerID, sessionToken)
}

// Verify checks that publicKey is an Ed25519 libp2p key, that peerIDStr is
// derived from it, and that signature is valid over message.
func Verify(publicKey []byte, peerIDStr string, message, signature []byte) error {
	pub, err := crypto.UnmarshalPublicKey(publicKey)
	if err != nil {
		return ErrInvalidPublicKey
	}
	if pub.Type() != pb.KeyType_Ed25519 {
		return ErrInvalidPublicKey
	}

	claimed, err := peer.Decode(peerIDStr)
	if err != nil {
		return ErrInvalidPeerID
	}
	derived, err := peer.IDFromPublicKey(pub)
	if err != nil {
		return ErrInvalidPublicKey
	}
	if claimed != derived || derived.String() != peerIDStr {
		return ErrPeerIDMismatch
	}

	ok, err := pub.Verify(message, signature)
	if err != nil || !ok {
		return ErrInvalidSignature
	}
	return nil
}
