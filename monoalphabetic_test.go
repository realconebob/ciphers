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

func TestAtbash(t *testing.T) {
	const PLAINTEXT string		= "SOILOOKEDANDSAWAWHITEHORSE"
	const CIPHERTEXT string		= "HLROLLPVWZMWHZDZDSRGVSLIHV"

	res1, err := Atbash(PLAINTEXT)
	if res1 != CIPHERTEXT || err != nil {
		t.Errorf("Got incorrect string from Atbash encryption: %v {%v}", res1, err)
	}

	res2, err := Atbash(res1)
	if res2 != PLAINTEXT || err != nil {
		t.Errorf("Got incorrect string from Atbash decryption: %v {%v}", res2, err)
	}
}

func Test_stripnonalpha(t *testing.T) {
	const UNSTRIPPED string = "This is a string!"
	const STRIPPED string	= "THISISASTRING"

	res, err := stripnonalpha(UNSTRIPPED)
	if res != STRIPPED || err != nil {
		t.Errorf("Got incorrect string from stripping function: %v (%v)", res, err)
	}
}

func TestCharacterFrequency(t *testing.T) {
	const EPSILON float64 = 0.01
	const SAMPLETEXT string = "" +
		"AND ONE BY ONE DROPPED THE REVELLERS IN THE BLOOD-BEDEWED HALLS OF THEIR REVEL, AND DIED EACH IN THE DESPAIRING POSTURE" + 
		"OF HIS FALL. AND THE LIFE OF THE EBONY CLOCK WENT OUT WITH THAT OF THE LAST OF THE GAY. AND THE FLAMES OF THE TRIPODS " + 
		"EXPIRED. AND DARKNESS AND DECAY AND THE RED DEATH HELD ILLIMITABLE DOMINION OVER ALL."
	/* Excerpt from Edgar Allan Poe's "Masque of the Red Death"
		Frequency analysis of all characters:
		Char	#	%
			E	39	12.11
			D	23	7.14
			T	21	6.52
			A	20	6.21
			O	19	5.9	
			H	18	5.59
			L	18	5.59
			N	17	5.28
			I	16	4.97
			R	12	3.73
			S	10	3.11
			F	9	2.8
			P	6	1.86
			B	5	1.55
			Y	4	1.24
			C	4	1.24
			V	3	0.93
			W	3	0.93
			.	3	0.93
			M	3	0.93
			G	2	0.62
			U	2	0.62
			K	2	0.62
			-	1	0.31
			,	1	0.31
			X	1	0.31

		E occurs 39 times and makes up 12.11% of the text. X occurs 1 time and makes up 0.31% of the text
	*/

	freqs, err := CharacterFrequency(SAMPLETEXT)
	if len(freqs) <= 0 || err != nil {
		t.Errorf("Couldn't generate character frequency: %v (%v)", freqs, err)
	}

	res := relativeError(freqs['E'], 0.1211)
	if res > EPSILON {
		t.Errorf("Expected frequency is out of range. Expected: %v, Got: %v", EPSILON, res)
	}

	res = relativeError(freqs['O'], 0.059)
	if res > EPSILON {
		t.Errorf("Expected frequency is out of range. Expected: %v, Got: %v", EPSILON, res)
	}
	
	res = relativeError(freqs['X'], 0.0031)
	if res > EPSILON {
		t.Errorf("Expected frequency is out of range. Expected: %v, Got: %v", EPSILON, res)
	}
}

func TestHomophonic(t *testing.T) {
	const PLAINTEXT string = "This is encrypted via (outdated) military encryption"

	res1, key1, err := HomophonicEncrypt(PLAINTEXT)
	if len(res1) <= 0 || len(key1) <= 0 || err != nil {
		t.Errorf("Got incorrect string from Homophonic encryption: %v %v (%v)", res1, key1, err)
	}

	res2, err := HomophonicDecrypt(res1, key1)
	if res2 != PLAINTEXT || err != nil {
		t.Errorf("Got incorrect string from Homophonic decryption: %v %v (%v)", res2, key1, err)
	}
}