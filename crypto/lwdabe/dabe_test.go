package lwdabe

import (
	//"basics/crypto/bn128"
	//"basics/crypto/lwdabe"
	"crypto/rand"
	bn128 "github.com/fentec-project/bn256"
	lib "github.com/fentec-project/gofe/abe"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMAABE(t *testing.T) {
	// create new MAABE struct with Global Parameters
	_, gt, _ := bn128.RandomGT(rand.Reader)
	KDF(gt)
	maabe := NewMAABE()

	// create three authorities, each with two attributes
	attribs1 := []string{"auth1:at1", "auth1:at2"}
	attribs2 := []string{"auth2:at1", "auth2:at2"}
	attribs3 := []string{"auth3:at1", "auth3:at2"}
	auth1, err := maabe.NewMAABEAuth("auth1", attribs1)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth1", err)
	}
	auth2, err := maabe.NewMAABEAuth("auth2", attribs2)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth2", err)
	}
	auth3, err := maabe.NewMAABEAuth("auth3", attribs3)
	if err != nil {
		t.Fatalf("Failed generation authority %s: %v\n", "auth3", err)
	}

	// create a msp struct out of the boolean formula
	msp, err := lib.BooleanToMSP("((auth1:at1 AND auth2:at1) OR (auth1:at2 AND auth2:at2)) OR (auth3:at1 AND auth3:at2)", false)
	if err != nil {
		t.Fatalf("Failed to generate the policy: %v\n", err)
	}

	// define the set of all public keys we use
	pks := []*MAABEPubKey{auth1.PubKeys(), auth2.PubKeys(), auth3.PubKeys()}

	// choose a message
	msg := "Attack at dawn!"

	// encrypt the message with the decryption policy in msp
	ct, err := maabe.Encrypt(msg, msp, pks)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v\n", err)
	}

	// also check for empty message
	msgEmpty := ""
	_, err = maabe.Encrypt(msgEmpty, msp, pks)
	assert.Error(t, err)

	// use a pub keyring that is too small
	pksSmall := []*MAABEPubKey{auth1.PubKeys()}
	_, err = maabe.Encrypt(msg, msp, pksSmall)
	assert.Error(t, err)

	// choose a single user's Global ID
	gid := "gid1"

	// authority 1 issues keys to user
	keys1, err := auth1.GenerateAttribKeys(gid, attribs1)
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	key11, key12 := keys1[0], keys1[1]
	// authority 2 issues keys to user
	keys2, err := auth2.GenerateAttribKeys(gid, attribs2)
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	key21, key22 := keys2[0], keys2[1]
	// authority 3 issues keys to user
	keys3, err := auth3.GenerateAttribKeys(gid, attribs3)
	if err != nil {
		t.Fatalf("Failed to generate attribute keys: %v\n", err)
	}
	key31, key32 := keys3[0], keys3[1]

	// try and generate key for an attribute that does not belong to the
	// authority (or does not exist)
	_, err = auth3.GenerateAttribKeys(gid, []string{"auth3:at3"})
	assert.Error(t, err)

	// user tries to decrypt with different key combos
	ks1 := []*MAABEKey{key11, key21, key31} // ok
	ks2 := []*MAABEKey{key12, key22, key32} // ok
	ks3 := []*MAABEKey{key11, key22}        // not ok
	ks4 := []*MAABEKey{key12, key21}        // not ok
	ks5 := []*MAABEKey{key31, key32}        // ok

	// try to decrypt all messages
	msg1, err := maabe.Decrypt(ct, ks1)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 1: %v\n", err)
	}
	assert.Equal(t, msg, msg1)

	msg2, err := maabe.Decrypt(ct, ks2)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 2: %v\n", err)
	}
	assert.Equal(t, msg, msg2)

	_, err = maabe.Decrypt(ct, ks3)
	assert.Error(t, err)

	_, err = maabe.Decrypt(ct, ks4)
	assert.Error(t, err)

	msg5, err := maabe.Decrypt(ct, ks5)
	if err != nil {
		t.Fatalf("Error decrypting with keyset 5: %v\n", err)
	}
	assert.Equal(t, msg, msg5)

	// generate keys with a different GID
	gid2 := "gid2"
	// authority 1 issues keys to user
	foreignKeys, err := auth1.GenerateAttribKeys(gid2, []string{"auth1:at1"})
	if err != nil {
		t.Fatalf("Failed to generate attribute key for %s: %v\n", "auth1:at1", err)
	}
	foreignKey11 := foreignKeys[0]
	// join two users who have sufficient attributes together, but not on their
	// own
	ks6 := []*MAABEKey{foreignKey11, key21}
	// try and decrypt
	_, err = maabe.Decrypt(ct, ks6)
	assert.Error(t, err)

	// add a new attribute to some authority
	err = auth3.AddAttribute("auth3:at3")
	if err != nil {
		t.Fatalf("Error adding attribute: %v\n", err)
	}
	// now try to generate the key
	_, err = auth3.GenerateAttribKeys(gid, []string{"auth3:at3"})
	if err != nil {
		t.Fatalf("Error generating key for new attribute: %v\n", err)
	}

	// regenerate a compromised key for some authority
	err = auth1.RegenerateKey("auth1:at2")
	if err != nil {
		t.Fatalf("Error regenerating key: %v\n", err)
	}
	// regenerate attrib key for that key and republish pubkey
	keysNew, err := auth1.GenerateAttribKeys(gid, []string{"auth1:at2"})
	if err != nil {
		t.Fatalf("Error generating attrib key for regenerated key: %v\n", err)
	}
	key12New := keysNew[0]
	pks = []*MAABEPubKey{auth1.Pk, auth2.Pk, auth3.Pk}
	// reencrypt msg
	ctNew, err := maabe.Encrypt(msg, msp, pks)
	if err != nil {
		t.Fatalf("Failed to encrypt with new keys")
	}
	ks7 := []*MAABEKey{key12New, key22}
	// decrypt reencrypted msg
	msg7, err := maabe.Decrypt(ctNew, ks7)
	if err != nil {
		t.Fatalf("Failed to decrypt with regenerated keys: %v\n", err)
	}
	assert.Equal(t, msg, msg7)
}
