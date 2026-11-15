// Package identity generates and loads the local Ed25519 agent key.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// LoadOrCreate reads a seed from keyPath or generates one. The public key is
// written next to it. Files are created with mode 0600.
func LoadOrCreate(keyPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(keyPath); err == nil {
		return keyFromFile(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	seed := priv.Seed()
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	pubPath := pubPathFor(keyPath)
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// LoadPublic reads the hex public key written by LoadOrCreate.
func LoadPublic(keyPath string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(pubPathFor(keyPath))
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(trim(string(b)))
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("identity: public key length")
	}
	return ed25519.PublicKey(raw), nil
}

func pubPathFor(keyPath string) string {
	if filepath.Ext(keyPath) == ".key" {
		return keyPath[:len(keyPath)-len(".key")] + ".pub"
	}
	return keyPath + ".pub"
}

func keyFromFile(b []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	raw, err := hex.DecodeString(trim(string(b)))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) != ed25519.SeedSize {
		return nil, nil, errors.New("identity: seed length")
	}
	priv := ed25519.NewKeyFromSeed(raw)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

func trim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}
