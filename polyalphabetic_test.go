package ciphers

import (
	"testing"
)

func TestVigenere(t *testing.T) {
	const PLAINTEXT string 	= "THYSECRETISTHYPRISONERIFTHOULETITGOTHOUARTAPRISONERTOIT"
	const KEYTEXT string 	= "ANDYETEMANCIPATEDITMUSTBE"
	const CIPHERTEXT string	= "UVCRJWWRUWVCXZJWMBIAZKCHYICYKJNNGHCWQEVUWXJJEDLIPJSHSHY"

	res, err := VigenereEncrypt(PLAINTEXT, KEYTEXT);
	if res != CIPHERTEXT || err != nil {
		t.Errorf("Got incorrect ciphertext or error after encryption: %v (%v)", res, err)
	}

	res, err = VigenereDecrypt(CIPHERTEXT, KEYTEXT);
	if res != PLAINTEXT || err != nil {
		t.Errorf("Got incorrect plaintext or error after decryption: %v (%v)", res, err)
	}
}
// 