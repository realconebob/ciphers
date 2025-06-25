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

	res1, err := keymapProcess(PT1, K1)
	if(res1 != CT1 || err != nil) {
		t.Errorf("Got incorrect string from MVPCProcess encryption: %v (%v)", res1, err)
	}

	res2, err := keymapProcess(res1, K1)
	if(res2 != PT1 || err != nil) {
		t.Errorf("Got incorrect string from MVPCProcess decryption: %v (%v)", res2, err)
	}


	res3, generated_key, err := MVPCEncrypt(PT1)
	if len(res3) <= 0 || generated_key == nil || err != nil {
		t.Errorf("Got incorrect string from MVPCEncrypt_gk encryption: %v %v (%v)", res3, generated_key, err)
	}
	res4, err := MVPCDecrypt(res3, generated_key)
	if res4 != PT1 || err != nil {
		t.Errorf("Got incorrect string from MVPCProcess decryption: %v %v (%v)", res4, generated_key, err)
	}
}

func TestROTX(t *testing.T) {
	const PLAINTEXT string 		= "VENI, VIDI, VICI"
	const CUT_PLAINTEXT string	= "VENIVIDIVICI"
	const CIPHERTEXT string 	= "YHQLYLGLYLFL"

	res1, err := CaesarEncrypt(PLAINTEXT)
	if res1 != CIPHERTEXT || err != nil {
		t.Errorf("Got incorrect string from Caesar encryption: %v (%v)", res1, err)
	}

	res2, err := CaesarDecrypt(res1)
	if res2 != CUT_PLAINTEXT || err != nil {
		t.Errorf("Got incorrect string from Caesar decryption: %v (%v)", res2, err)
	}


	const PT2 string = "SECONDMESSAGE"
	const CT2 string = "GSQCBRASGGOUS"
	const OFFSET rune = 14

	res3, err := ROTX(PT2, OFFSET)
	if res3 != CT2 || err != nil {
		t.Errorf("Got incorrect string from ROTX encryption: %v (%v)", res3, err)
	}

	res4, err := ROTX(res3, -1 * OFFSET)
	if res4 != PT2 || err != nil {
		t.Errorf("Got incorrect string from ROTX decryption: %v (%v)", res4, err)
	}
}

func TestKeyphrase(t *testing.T) {
	const PLAINTEXT string 	= "ETTUBRUTE"
	const KEYTEXT string	= "BEWAREIDES"
	const CIPHERTEXT string = "RKKLEHLKR"

	res1, err := KeyphraseEncrypt(PLAINTEXT, KEYTEXT)
	if res1 != CIPHERTEXT || err != nil {
		t.Errorf("Got incorrect string from Keyphrase encryption: %v (%v)", res1, err)
	}

	res2, err := KeyphraseDecrypt(res1, KEYTEXT)
	if res2 != PLAINTEXT || err != nil {
		t.Errorf("Got incorrect string from Keyphrase decryption: %v (%v)", res2, err)
	}
}