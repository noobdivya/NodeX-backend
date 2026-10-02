// Command nodex-node runs a NodeX P2P network node.
//
// It is a regular libp2p peer — not an account server. It:
//   - lets browsers join the network (they can't accept incoming
//     connections, so they dial nodes like this one over WebSockets),
//   - takes part in the NodeX DHT (protocol /nodex/kad/1.0.0), holding the
//     public, signed handle records peers publish, in memory only,
//   - offers a circuit relay so browsers can later reach each other.
//
// It has no database and no user accounts. Anyone can run one; several
// nodes can be linked with NODE_PEERS.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/libp2p/go-libp2p/p2p/transport/websocket"
)

func main() {
	listen := splitList(getenv("NODE_LISTEN", "/ip4/0.0.0.0/tcp/4001,/ip4/0.0.0.0/tcp/4002/ws"))
	keyFile := getenv("NODE_KEY_FILE", "node.key")

	priv, err := loadOrCreateKey(keyFile)
	if err != nil {
		log.Fatalf("node key: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listen...),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Transport(websocket.New),
		// Relayed connections are a fallback when two browsers can't connect
		// directly. The default limit (128 KB, 2 min) is too small for photo
		// messages, so allow more. The relay only ever sees encrypted bytes.
		libp2p.EnableRelayService(relay.WithLimit(&relay.RelayLimit{
			Duration: 10 * time.Minute,
			Data:     16 << 20,
		})),
		libp2p.ForceReachabilityPublic(),
	)
	if err != nil {
		log.Fatalf("libp2p: %v", err)
	}
	defer h.Close()

	var bootstrap []peer.AddrInfo
	for _, s := range splitList(os.Getenv("NODE_PEERS")) {
		ai, err := peer.AddrInfoFromString(s)
		if err != nil {
			log.Fatalf("NODE_PEERS: %q: %v", s, err)
		}
		bootstrap = append(bootstrap, *ai)
	}

	kad, err := dht.New(h,
		dht.Mode(dht.ModeServer),
		dht.ProtocolPrefix("/nodex"),
		dht.NamespacedValidator(recordNamespace, NewValidator()),
		dht.BootstrapPeers(bootstrap...),
	)
	if err != nil {
		log.Fatalf("dht: %v", err)
	}
	defer kad.Close()
	if err := kad.Bootstrap(ctx); err != nil {
		log.Printf("dht bootstrap: %v", err)
	}
	for _, ai := range bootstrap {
		if err := h.Connect(ctx, ai); err != nil {
			log.Printf("connect %s: %v", ai.ID, err)
		}
	}

	log.Printf("NodeX node %s", h.ID())
	for _, a := range h.Addrs() {
		log.Printf("  listening on %s/p2p/%s", a, h.ID())
	}
	for _, a := range listen {
		if strings.HasSuffix(a, "/ws") {
			local := strings.Replace(a, "/ip4/0.0.0.0/", "/ip4/127.0.0.1/", 1)
			log.Printf("browsers (local dev): NEXT_PUBLIC_BOOTSTRAP_PEERS=%s/p2p/%s", local, h.ID())
		}
	}

	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-t.C:
			log.Printf("peers connected: %d, dht routing table: %d", len(h.Network().Peers()), kad.RoutingTable().Size())
		}
	}
}

// loadOrCreateKey keeps the node's identity stable across restarts, so its
// address (which browsers are configured with) doesn't change.
func loadOrCreateKey(path string) (crypto.PrivKey, error) {
	if seed := os.Getenv("NODE_KEY"); seed != "" {
		return keyFromHex(seed)
	}
	data, err := os.ReadFile(path)
	if err == nil {
		return keyFromHex(strings.TrimSpace(string(data)))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, err
	}
	log.Printf("created new node identity in %s (keep it to keep the same node address)", path)
	return keyFromHex(hex.EncodeToString(seed))
}

func keyFromHex(s string) (crypto.PrivKey, error) {
	seed, err := hex.DecodeString(s)
	if err != nil || len(seed) != 32 {
		return nil, fmt.Errorf("node key must be 64 hex characters")
	}
	return crypto.UnmarshalEd25519PrivateKey(ed25519.NewKeyFromSeed(seed))
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
