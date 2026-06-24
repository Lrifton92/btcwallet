// Copyright (c) 2026 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package vaultmock

import (
	"context"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/keyvault"
	"github.com/stretchr/testify/mock"
)

// Vault is a testify-based mock for the wallet key-vault interface.
type Vault struct {
	mock.Mock
}

// Ensure Vault implements the keyvault.Vault interface.
var _ keyvault.Vault = (*Vault)(nil)

// Encrypt forwards to the configured testify expectations.
func (m *Vault) Encrypt(keyType waddrmgr.CryptoKeyType,
	plaintext []byte) ([]byte, error) {

	args := m.Called(keyType, plaintext)

	return returnBytes(args, keyType, plaintext), args.Error(1)
}

// Decrypt forwards to the configured testify expectations.
func (m *Vault) Decrypt(keyType waddrmgr.CryptoKeyType,
	ciphertext []byte) ([]byte, error) {

	args := m.Called(keyType, ciphertext)

	return returnBytes(args, keyType, ciphertext), args.Error(1)
}

// DerivePubKey forwards to the configured testify expectations.
func (m *Vault) DerivePubKey(ctx context.Context,
	ref keyvault.KeyLocator) (*btcec.PublicKey, error) {

	args := m.Called(ctx, ref)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	pk, ok := args.Get(0).(*btcec.PublicKey)
	if !ok {
		return nil, args.Error(1)
	}

	return pk, args.Error(1)
}

// SignECDSA forwards to the configured testify expectations.
func (m *Vault) SignECDSA(ctx context.Context, ref keyvault.KeyLocator,
	digest [32]byte) (*ecdsa.Signature, error) {

	args := m.Called(ctx, ref, digest)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	sig, ok := args.Get(0).(*ecdsa.Signature)
	if !ok {
		return nil, args.Error(1)
	}

	return sig, args.Error(1)
}

// SignCompactECDSA forwards to the configured testify expectations.
func (m *Vault) SignCompactECDSA(ctx context.Context, ref keyvault.KeyLocator,
	digest [32]byte, compressed bool) ([]byte, error) {

	args := m.Called(ctx, ref, digest, compressed)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	b, ok := args.Get(0).([]byte)
	if !ok {
		return nil, args.Error(1)
	}

	return b, args.Error(1)
}

// SignSchnorr forwards to the configured testify expectations.
func (m *Vault) SignSchnorr(ctx context.Context, ref keyvault.KeyLocator,
	digest [32]byte) (*schnorr.Signature, error) {

	args := m.Called(ctx, ref, digest)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	sig, ok := args.Get(0).(*schnorr.Signature)
	if !ok {
		return nil, args.Error(1)
	}

	return sig, args.Error(1)
}

// SignTweakedSchnorr forwards to the configured testify expectations.
func (m *Vault) SignTweakedSchnorr(ctx context.Context,
	ref keyvault.KeyLocator, digest [32]byte,
	tweak keyvault.SchnorrKeyTweak) (*schnorr.Signature, error) {

	args := m.Called(ctx, ref, digest, tweak)

	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	sig, ok := args.Get(0).(*schnorr.Signature)
	if !ok {
		return nil, args.Error(1)
	}

	return sig, args.Error(1)
}

// Unlock forwards to the configured testify expectations.
func (m *Vault) Unlock(ctx context.Context, passphrase []byte) error {
	args := m.Called(ctx, passphrase)
	return args.Error(0)
}

// Lock forwards to the configured testify expectations.
func (m *Vault) Lock() {
	m.Called()
}

// IsLocked forwards to the configured testify expectations.
func (m *Vault) IsLocked() bool {
	args := m.Called()
	return args.Bool(0)
}

// ChangePassphrase forwards to the configured testify expectations.
func (m *Vault) ChangePassphrase(ctx context.Context,
	passphrase []byte) error {

	args := m.Called(ctx, passphrase)
	return args.Error(0)
}

// returnBytes resolves the first programmed Return arg into a byte slice.
func returnBytes(args mock.Arguments, keyType waddrmgr.CryptoKeyType,
	input []byte) []byte {

	if fn, ok := args.Get(0).(func(waddrmgr.CryptoKeyType, []byte) []byte); ok {
		return fn(keyType, input)
	}

	if args.Get(0) == nil {
		return nil
	}

	b, ok := args.Get(0).([]byte)
	if !ok {
		return nil
	}

	return b
}
