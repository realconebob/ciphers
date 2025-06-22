package ciphers

import (
	"testing"
)

func TestRailfence(t *testing.T) {
	const PLAINTEXT string 		= "THYSECRETISTHYPRISONERIFTHOULETITGOTHOUARTAPRISONERTOIT"
	const CIPHERTEXT string 	= "TYERTSHPIOEITOLTTOHURARSNROTHSCEITYRSNRFHUEIGTOATPIOETI"

	res, err := RailfenceEncrypt(PLAINTEXT)
	if(res != CIPHERTEXT || err != nil) {
		t.Errorf("Got incorrect string during encryption: %v (%v)", res, err)
	}

	res, err = RailfenceDecrypt(CIPHERTEXT)
	if(res != PLAINTEXT || err != nil) {
		t.Errorf("Got incorrect string during decryption: %v (%v)", res, err)
	}
}