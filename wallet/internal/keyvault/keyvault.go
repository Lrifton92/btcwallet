// Package keyvault defines the encryption boundary for wallet key material.
package keyvault

import (
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcwallet/waddrmgr"
)

// ErrInvalidPassphrase reports that the provided vault passphrase is wrong.
var ErrInvalidPassphrase = errors.New("invalid vault passphrase")

// ErrVaultLocked reports that an operation requiring unlocked runtime state
// was attempted while the vault was locked.
var ErrVaultLocked = errors.New("vault is locked")

// ErrVaultUnlocked reports that an unlock operation was attempted while the
// vault was already unlocked.
var ErrVaultUnlocked = errors.New("vault is already unlocked")

// ErrVaultSigningUnimplemented reports that the vault does not implement key
// signing yet.
var ErrVaultSigningUnimplemented = errors.New("vault signing is unimplemented")

// KeyLocator identifies a key using one of the vault's supported reference
// forms.
type KeyLocator struct {
	// FullHD names a complete wallet-root derivation path.
	FullHD *FullHDKeyRef

	// AccountKey names a child under a persisted account row, including
	// imported xkey accounts.
	AccountKey *AccountKeyRef

	// ScriptPubKey names a raw imported address or private-key row by script
	// pubkey.
	ScriptPubKey *ScriptPubKeyRef
}

// FullHDKeyRef identifies a complete wallet-root derivation path.
type FullHDKeyRef struct {
	// Purpose is the BIP purpose component.
	Purpose uint32

	// Coin is the BIP coin-type component.
	Coin uint32

	// Account is the BIP account component.
	Account uint32

	// Branch is the branch within the account.
	Branch uint32

	// Index is the address index within the branch.
	Index uint32
}

// AccountKeyRef identifies a child under a persisted account row.
type AccountKeyRef struct {
	// AccountID is the persisted account row identifier.
	AccountID uint32

	// Branch is the branch within the account.
	Branch uint32

	// Index is the key index within the branch.
	Index uint32
}

// ScriptPubKeyRef identifies a raw imported row by script pubkey.
type ScriptPubKeyRef struct {
	// ScriptPubKey is the raw locking script.
	ScriptPubKey []byte
}

// SchnorrKeyTweak describes an additive secp256k1 tweak for Schnorr signing.
type SchnorrKeyTweak struct {
	// Tweak is the 32-byte additive scalar.
	Tweak [32]byte

	// NormalizeEvenY reports whether the key should be normalized to the
	// BIP340 even-Y representative before the tweak is applied.
	NormalizeEvenY bool
}

// Vault manages the lock lifecycle and cryptographic operations for wallet key
// material.
// It is intentionally aggregated as the wallet-scoped boundary for lock,
// encryption, derivation, and signing lifecycle.
//
//nolint:interfacebloat
type Vault interface {
	// Unlock unlocks the vault with the provided passphrase.
	//
	// If the passphrase is invalid, or the unlock operation fails, the vault
	// must remain locked. If Unlock is called while the vault is already
	// unlocked, it must return ErrVaultUnlocked without validating the provided
	// passphrase.
	Unlock(ctx context.Context, passphrase []byte) error

	// Lock locks the vault and erases secret material from memory. Lock is
	// idempotent.
	Lock()

	// IsLocked reports whether the vault is currently locked.
	IsLocked() bool

	// Encrypt encrypts plaintext key material with the selected crypto key
	// type.
	Encrypt(keyType waddrmgr.CryptoKeyType, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext key material with the selected crypto key
	// type.
	Decrypt(keyType waddrmgr.CryptoKeyType, ciphertext []byte) ([]byte, error)

	// ChangePassphrase rotates persisted wallet secrets to the provided new
	// private passphrase. The vault must already be unlocked when this method
	// is called.
	ChangePassphrase(ctx context.Context, newPassphrase []byte) error

	// DerivePubKey derives the public key for the provided key locator.
	//
	// The caller provides a wallet key locator, and the vault returns the
	// corresponding public key without exposing private key material.
	DerivePubKey(ctx context.Context, ref KeyLocator) (*btcec.PublicKey, error)

	// SignECDSA signs a caller-computed 32-byte digest for the provided key
	// locator.
	//
	// The caller is responsible for digest construction, sighash selection,
	// signature serialization, and transaction assembly.
	SignECDSA(ctx context.Context, ref KeyLocator,
		digest [32]byte) (*ecdsa.Signature, error)

	// SignCompactECDSA signs a caller-computed 32-byte digest and returns a
	// compact recoverable signature for the provided key locator.
	//
	// The caller is responsible for digest construction, compressed-key header
	// semantics, signature serialization, and transaction assembly.
	SignCompactECDSA(ctx context.Context, ref KeyLocator, digest [32]byte,
		compressed bool) ([]byte, error)

	// SignSchnorr signs a caller-computed 32-byte digest for the provided key
	// locator.
	//
	// The caller is responsible for digest construction, sighash selection,
	// signature serialization, and transaction assembly.
	SignSchnorr(ctx context.Context, ref KeyLocator,
		digest [32]byte) (*schnorr.Signature, error)

	// SignTweakedSchnorr signs a caller-computed 32-byte digest after applying
	// the provided additive tweak descriptor.
	//
	// The caller is responsible for taproot output construction, digest
	// construction, signature serialization, and any appended sighash byte.
	SignTweakedSchnorr(ctx context.Context, ref KeyLocator,
		digest [32]byte, tweak SchnorrKeyTweak) (*schnorr.Signature, error)
}
