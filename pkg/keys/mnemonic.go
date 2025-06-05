package keys

import (
	"fmt"

	"github.com/alexvec/go-bip39"
	"github.com/alexvec/gotron-sdk/pkg/keys/hd"
	"github.com/btcsuite/btcd/btcec/v2"
)

// FromMnemonicSeedAndPassphrase derive form mnemonic and passphrase at index
func FromMnemonicSeedAndPassphrase(mnemonic, passphrase string, index int) (*btcec.PrivateKey, *btcec.PublicKey) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	master, ch := hd.ComputeMastersFromSeed(seed, []byte("Bitcoin seed"))
	private, _ := hd.DerivePrivateKeyForPath(
		btcec.S256(),
		master,
		ch,
		fmt.Sprintf("44'/195'/0'/0/%d", index),
	)

	return btcec.PrivKeyFromBytes(private[:])
}
