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
	"errors"
	"fmt"
	"math"
	"math/rand"
	"slices"
	"strings"
)

func stripnonalpha(text string) (string, error) {
    if len(text) <= 0 {return "", errors.New("given empty string")}
    var res string

    for _, cur := range text {
        if(cur >= 'a' && cur <= 'z') {cur -= 'a' - 'A'}
        if(cur < 'A' || cur > 'Z') {continue}
        res += string(cur)
    }

    return res, nil
}

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

// I realized that I am going to be regularly mapping a set of things to some set of key values and that it would be easier to have a generic function for it than redoing it every time
func automap[K comparable, V any](iterable []K, key map[K]V) ([]V, error) {
    if len(iterable) <= 0 {return nil, errors.New("got empty slice")}
    if len(key) <= 0 {return nil, errors.New("got empty key")}
    var res []V

    for _, cur := range iterable {
        res = append(res, key[cur])
    }

    return res, nil
}

func keymapProcess(text string, key map[rune]rune) (string, error) {
    if len(text) <= 0 || len(key) <= 0 {return "", errors.New("given an empty string")}

    inter, err := automap([]rune(text), key)
    if len(inter) <= 0 || err != nil {return "", err}

    return string(inter), nil
}

func MVPCEncrypt(plaintext string) (string, map[rune]rune, error) {
    var key map[rune]rune = make(map[rune]rune, 26)

    // Populate key
        // Get 2 letters at random
        // Create the pairing 
        // Repeat until all letters are consumed

    // Note: I'm not going to bother with cryptographically secure randomness as there's no point with a cipher so simple

    var letters []rune = []rune(ROMANALPHA)
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

    ciphertext, err := keymapProcess(plaintext, key)
    if(err != nil) {return "", nil, err}
    return ciphertext, key, nil
}

func MVPCDecrypt(ciphertext string, key map[rune]rune) (string, error) {
    return keymapProcess(ciphertext, key)
}

/* The Caesar cipher (and subsequently ROTX ciphers) is(/are) possibly the most famous cipher(s) to exist. I chalk this up to the
connection to Julius Caesar, and its ease of use for school children. The Caesar cipher takes an alphabet and rotates it by 3
characters; this operation turns A into D, B into E, C into F, and so on. This was, and arguably still is, done via a cipherwheel,
which consists of 2 wheels with each letter of the alphabet inscribed on the outter edge. To get a new cipheralphabet, just rotate
one of the wheels by some number of times, and translate from top wheel into bottom. To decipher you'd set the same rotation, then
read from the inner wheel to the outter

The ROTX cipher is "Rotational X", and the Caesar cipher a specific ROTX variant (specifically ROT+3), where the wheel is
incremented in a direction some amount of times

Here's the example in the book:

    Key:
        ABCDEFGHIJKLMNOPQRSTUVWXYZ
        DEFGHIJKLMNOPQRSTUVWXYZABC

    Plaintext:
        VENI, VIDI, VICI
    Ciphertext:
        YHQL YLGL YLFL
*/

func ROTX(text string, offset rune) (string, error) {
    if len(text) <= 0               {return "", errors.New("given empty string")}
    if offset % rune(ROMANWIDTH) == 0    {return "", errors.New("given offset that would not meaningfully encrypt message (" + string(offset) + " % " + fmt.Sprintf("%d", ROMANWIDTH) + " == 0)")}
    var res string


    for ; offset < 0; offset += rune(ROMANWIDTH) {}
    for _, cur := range text {
        if cur < 'A' || cur > 'Z' {continue}
        res += string(((cur - 'A' + offset) % rune(ROMANWIDTH)) + 'A') 
    }   

    return res, nil
}

func CaesarEncrypt(text string) (string, error) {
    return ROTX(text, 3)
}

func CaesarDecrypt(text string) (string, error) {
    return ROTX(text, -3)
}


/* The Simple Keyphrase cipher is the first cipher to meaningfully stump cryptanalysts for any real period of time, and remains
quite simple on top of that. The problem with the ROTX cipher and its variants is that they have a very small keyspace. There are
only 26 possible cipher alphabets when using ROTX, which means it's trivial to crack any ciphertext "protected" by it. You don't
even need to check the entire text, just a few starting words to see if that cipheralphabet is making coherent results. With the
keyphrase cipher, the number of possible cipher alphabets expands to 26!, or 4.0329146113 * 10^26. This number of combinations is
simply too numerous for anyone, even a team of people, to run through, and because frequency analysis wasn't a widely known thing
this cipher remained strong for a long time

To use this cipher, simply come up with a keyphrase, remove any duplicate letters, fill in the rest of the alphabet, and substitute
plaintext letters accordingly. Here's the book's example:

    Keyphrase:
        Julius Caesar

    Fixed Keyphrase: 
        JULISCAER

    Full Cipheralphabet:
        JULISCAERTVWXYZBDFGHKMNOPQ
*/

func keyphraseProcess(text, keyphrase string, mode bool) (string, error) {
    if len(text) <= 0 || len(keyphrase) <= 0 {return "", errors.New("given empty string")}
    var key map[rune]rune = make(map[rune]rune, 26)
    var set GSet[rune] = NewGSet[rune]()

    // The last element of keyphrase is, or rather contains, the index of where the romanalpha slice should start
        // Ex: last letter is 'R', 'R' - 'A' is the index of 'R' in ROMANALPHA
    var kpstr []rune = []rune(keyphrase + ROMANALPHA[[]rune(keyphrase)[len(keyphrase) - 1] - 'A' + 1:] + ROMANALPHA[:[]rune(keyphrase)[len(keyphrase) - 1] - 'A'])

    // For each letter in the alphabet:
        // Check to see if the letter has already been mapped
            // If not, map the letter and continue
            // If so, move to the next letter in the mapping
                // If keyphrase has been consumed, continue with the rest of the alphabet from the end of the phrase

    for ind := 0; len(kpstr) > 0; {
        if !set.check(kpstr[0]) {
            set.add(kpstr[0])
            key[[]rune(ROMANALPHA)[ind]] = kpstr[0]
            ind++
        }

        kpstr = slices.Delete(kpstr, 0, 1)
    }

    // (Decryption) Invert the key map so that the current ABCD... -> XXXX... map becomes XXXX.... -> ABCD...
    if mode {
        temp := make(map[rune]rune, 26)
        for k, v := range key {
            temp[v] = k
        }
        key = temp
    }

    // Process data
    res, err := keymapProcess(text, key)
    if len(res) <= 0 || err != nil {
        return "", errors.New("could not process text")
    }

    return res, nil
}

func KeyphraseEncrypt(text, keyphrase string) (string, error) {
    return keyphraseProcess(text, keyphrase, false)
}

func KeyphraseDecrypt(text, keyphrase string) (string, error) {
    return keyphraseProcess(text, keyphrase, true)
}


/* Atbash is an interesting cipher due to it's origin, that being the Bible (old testament specifically). It's quite simple, as
all it does is replace letters with their "opposites". A becomes Z, B becomes Y, C becomes X, and so on */

func Atbash(text string) (string, error) {
    if len(text) <= 0 {return "", errors.New("given empty string")}
    var res string

    for _, cur := range text {
        res += string('Z' - cur + 'A')
    }

    return res, nil
}

/* The Homophonic Substitution Cipher was the military's solution to encryption in an age before the widespread adoption of the 
Vigenere Cipher. Enciphering via Vigenere was considered too complicated / costly, but a straightforward substitution cipher was
considered too weak, so cryptographers needed an intermediary option. They settled on the homophonic substitution cipher, a cipher
where each letter of the language is represented by a number of symbols equivalent to its average usage. For example: the letter 'a'
makes up about 8% of any large enough english text, so it is represented by at least 8 symbols as to make any individual 
representing symbol only make up 1% of the text. This would theoretically render the text immune to basic frequency analysis, which
it did make freq.an. harder, but did not meaningfully thwart it. Regardless, it remained effective for quite some time
*/

func keyFreq[K comparable](keylist []K) (map[K]float64, error) {
    if len(keylist) <= 0 {return nil, errors.New("given empty keylist")}
    var res map[K]float64 = make(map[K]float64)

    for _, key := range keylist {
        res[key] += 1
    }
    for key := range res {
        res[key] /= float64(len(keylist) /* brain moment */)
    }

    return res, nil
}

func CharacterFrequency(text string) (map[rune]float64, error) {
    if len(text) <= 0 {return nil, errors.New("got empty string")}
    return keyFreq([]rune(text))
}

// Set the symbol range to something higher than you think you'll need. Might take a long time to generate the symbols otherwise
func HomophonicEncrypt(plaintext string, symbolrange int) (string, map[string]rune, error) {
    if len(plaintext) <= 0  {return "", nil, errors.New("given empty string")}
    var ciphertext string
    var key map[string]rune = make(map[string]rune)
    var internalkey map[rune][]string = make(map[rune][]string) 
    var usedsymbols GSet[string] = NewGSet[string]()

    // Populate the key
        // Get the frequencies of each character in the plaintext
        // Convert the frequencies into counts by multiplying by 100 and rounding to the next highest int
        // Set count to 2 if less than 2
        // Create `count` symbols, add them to the usedsymbols set, internal key array for that given symbol, and key

    freqs, err := CharacterFrequency(plaintext)
    if len(freqs) <= 0 || err != nil {return "", nil, err}

    for char, freq := range freqs {
        freq *= 100
        freq = math.Ceil(freq)
        if freq < 2 {freq = 2}

        for i := 0; i < int(freq); i++ {
            // Get a new, unused symbol
            symbol := fmt.Sprint(rand.Intn(symbolrange + 1))
            for ; usedsymbols.check(symbol); symbol = fmt.Sprint(rand.Intn(symbolrange + 1)) {}

            // Add symbol to keys and set
            internalkey[char] = append(internalkey[char], symbol)
            key[symbol] = char
            usedsymbols.add(symbol)
        }
    }

    // Populate the ciphertext
        // For each letter in the ciphertext, get the array of possible symbols via the internal key
        // Pick a random symbol from the array
        // Append it to the ciphertext

    for _, cur := range plaintext {
        psymbols := internalkey[cur]
        choice := rand.Intn(len(psymbols))
        ciphertext += psymbols[choice] + " "
    }
    ciphertext = string(slices.Delete([]rune(ciphertext), len(ciphertext) - 1, len(ciphertext)))

    return ciphertext, key, nil
}
func HomophonicDecrypt(ciphertext string, key map[string]rune) (string, error) {
    if len(ciphertext) <= 0 {return "", errors.New("given empty string")} 
    if len(key) <= 0 {return "", errors.New("given empty map")} 

    var temp []string = strings.Split(ciphertext, " ")
    plaintext, err := automap(temp, key)
    return string(plaintext), err
}