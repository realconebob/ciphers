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

func TestMVPC(t *testing.T) {
	const PT1 string = "MEETATMIDNIGHT"
	const CT1 string = "CUUZVZCGXSGIBZ"
	K1 := map[rune]rune{
		'A': 'V', 'B': 'H', 'C': 'M', 'D': 'X',
		'E': 'U', 'F': 'W', 'G': 'I', 'H': 'B',
		'I': 'G', 'J': 'K', 'K': 'J', 'L': 'R',
		'M': 'C', 'N': 'S', 'O': 'Q', 'P': 'Y',
		'Q': 'O', 'R': 'L', 'S': 'N', 'T': 'Z',
		'U': 'E', 'V': 'A', 'W': 'F', 'X': 'D',
		'Y': 'P', 'Z': 'T',
	}

	res1, err := MVPCProcess(PT1, K1)
	if(res1 != CT1 || err != nil) {
		t.Errorf("Got incorrect string from MVPCProcess encryption: %v (%v)", res1, err)
	}

	res2, err := MVPCProcess(res1, K1)
	if(res2 != PT1 || err != nil) {
		t.Errorf("Got incorrect string from MVPCProcess decryption: %v (%v)", res2, err)
	}


	res3, generated_key, err := MVPCEncrypt_gk(PT1)
	if len(res3) <= 0 || generated_key == nil || err != nil {
		t.Errorf("Got incorrect string from MVPCEncrypt_gk encryption: %v %v (%v)", res3, generated_key, err)
	}
	res4, err := MVPCProcess(res3, generated_key)
	if res4 != PT1 || err != nil {
		t.Errorf("Got incorrect string from MVPCProcess decryption: %v %v (%v)", res4, generated_key, err)
	}
}