/** MONOALPHABETIC CIPHERS
- "A substitution cipher in which the cipher alphabet is fixed throughout encryption", page 393

Monoalphabetic ciphers tend to be much less secure than any type of polyalphabetic substitution cipher, as they are vulnerable to
frequency analysis. Even the most clever ways of trying to fool frequency analysis are eventually thwarted, and so they have
generally fallen out of use (the notable exception being kids in school, such as myself 7 years ago). That being said, thinking about
how to make an MSC more secure to freq.an. is an interesting thought experiment, and something I think would be valuable even if
still ultimately insecure

Ciphers implemented in this file:
    - "Rail Fence" Transposition Cipher (Page 8)
    - Mlecchita-vikalpa Pairing Cipher (Page 9)
    - Caesar / ROTX Cipher (Page 10)
    - Simple Keyphrase Cipher (Page 13)
    - Atbash (Page 26)
    - Homophonic Substitution Cipher (Page 52)
    - Book Cipher (Page 90)
*/

package ciphers

import (
    "strings"
    "errors"
    "math/rand"
    "slices"
)

/* The "Rail Fence" Cipher is a simple transposition cipher, meaning it simply rearranges the order of the letters contained in the
plaintext. Here is an example from The Code Book: (page 8)

    Plaintext:  THY SECRET IS THY PRISONER; IF THOU LET IT GO, THOU ART A PRISONER TO IT
    
    Step 1 - Remove puncuation & whitespace:
        THYSECRETISTHYPRISONERIFTHOULETITGOTHOUARTAPRISONERTOIT
    
    Step 2 - Break into 2 "rails":
        T Y E R T S H P I O E I T O L T T O H U R A R S N R O T
         H S C E I T Y R S N R F H U E I G T O A T P I O E T I
    
    Step 3 - Append 2nd rail to 1st:
        T Y E R T S H P I O E I T O L T T O H U R A R S N R O T H S C E I T Y R S N R F H U E I G T O A T P I O E T I
    
    Step 4 (End) - Remove whitespace again: 
        TYERTSHPIOEITOLTTOHURARSNROTHSCEITYRSNRFHUEIGTOATPIOETI

    Ciphertext: TYERTSHPIOEITOLTTOHURARSNROTHSCEITYRSNRFHUEIGTOATPIOETI

    
    To decipher, split the ciphertext into 2 strings at the middle, then reconstruct character by character:
    
    Ciphertext: TYERTSHPIOEITOLTTOHURARSNROTHSCEITYRSNRFHUEIGTOATPIOETI
    Step 1 - Split into 2 strings, starting in the middle:
        TYERTSHPIOEITOLTTOHURARSNROT
        HSCEITYRSNRFHUEIGTOATPIOETI
    Step 2 - Reconstruct plaintext, taking a character from the top, then the bottom, until running out of characters:
        THYSECRETISTHYPRISONERIFTHOULETITGOTHOUARTAPRISONERTOIT
*/

// Encipher a plaintext via the Rail Fence Transposition Cipher
func RailfenceEncrypt(plaintext string) (string, error) {
    if(len(plaintext) <= 0) {return "", errors.New("given empty string")}

    var halves [2]string
    var chars []string = strings.Split(plaintext, "")

    for i := 0; i < len(plaintext); i++ {
        halves[i%2] += chars[i]
    }

    return halves[0] + halves[1], nil
}

// Decipher a ciphertext via the Rail Fence Transposition Cipher
func RailfenceDecrypt(ciphertext string) (string, error) {
    if(len(ciphertext) <= 0) {return "", errors.New("given empty string")}

    var res string
    var halves [2][]rune
    var h1l int = len(ciphertext)/2
    if(len(ciphertext)%2==1) {h1l++}

    halves[0] = []rune(ciphertext)[0:h1l]
    halves[1] = []rune(ciphertext)[h1l:]
    
    for i, j, t := 0, 0, 0; t < len(ciphertext); t++ {
        if(t%2==0) {
            res += string(halves[0][i])
            i++
        } else {
            res += string(halves[1][j])
            j++
        }
        // Yeah this is not great but it works
    }

    return res, nil
}


/* The Mlecchita-vikalpa Pairing Cipher is a simple substitution cipher where 2 letters of an alphabet are paired. This pair is then
used as the "key" for encryption and decryption. To encrypt a piece of plaintext, take letter and map it to its pair. This is
highlighted with an example on page 9:

    Key:    ADHIKMORSUWYZ
            VXBGJCQLNEFPT

    Plaintext:
        Meet at midnight
    Ciphertext:
        CUUZ VZ CGXSGIBZ

    To decipher, repeat the mapping process with the ciphertext
*/

func MVPCProcess(text string, key map[rune]rune) (string, error) {
    if len(text) <= 0 || len(key) <= 0 {return "", errors.New("given an empty string")}

    var ciphertext string
    var mres rune

    for _, cur := range text {
        mres = key[cur]
        if(mres == 0) {return "", errors.New("character \"" + string(cur) + "\" does not exist in key")}

        ciphertext += string(mres)
    }

    return ciphertext, nil
}

func MVPCEncrypt_gk(plaintext string) (string, map[rune]rune, error) {
    var key map[rune]rune = make(map[rune]rune, 26)

    // Populate key
        // Get 2 letters at random
        // Create the pairing 
        // Repeat until all letters are consumed

    // Note: I'm not going to bother with cryptographically secure randomness as there's no point with a cipher so simple

    var letters []rune = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    var lp [2]rune
    for ; len(letters) > 0; {
        for i, randi := 0, 0; i < 2; i++ {
            randi = rand.Intn(len(letters))
            lp[i] = letters[randi]
            letters = slices.Delete(letters, randi, randi + 1)
        }
        // Doing it like this means I'm not dealing with (literally) random oob panics

        key[lp[0]] = lp[1]
        key[lp[1]] = lp[0]
    }

    ciphertext, err := MVPCProcess(plaintext, key)
    if(err != nil) {return "", nil, err}
    return ciphertext, key, nil
}