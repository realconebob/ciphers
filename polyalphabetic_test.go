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

func TestOTP(t *testing.T) {
	const PLAINTEXT string = "WELLANDTRULYUNBREAKABLE"
	
	res1, key, err := OTPEncrypt(PLAINTEXT)
	if len(res1) <= 0 || len(key) <= 0 || err != nil {
		t.Errorf("Got incorrect output from OPTEncrypt: %v %v (%v)", res1, key, err)
	}

	res2, err := OTPDecrypt(res1, key)
	if res2 != PLAINTEXT || err != nil {
		t.Errorf("Got incorrect output from OPTDecrypt: %v %v (%v)", res2, key, err)
	}
}