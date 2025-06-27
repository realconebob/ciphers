/** POLYALPHABETIC CIPHERS
- "A substitution cipher in which the cipher alphabet changes during the encryption, for example the Vigenere cipher.
    The change is defined by a key", page 393

Polyalphabetic ciphers are by default more secure than monoalphabetic ciphers, even in the case of the relatively simplistic
Vigenere cipher, simply because breaking the cipher will generally require several passes of freq.an., if freq.an. is even an
applicable solution to deciphering. All modern, secure encryption schemes use some form of polyalphabetic cipher, as it still
remains unmatched. Mind you, it is still possible to create an insecure polyalphabetic substitution cipher, it's just that by
taking the proper precautions, most attacks can be mitigated (even if they're still technically possible)

Ciphers implemented in this file:
    - Vigenere Cipher (Page 45)
    - One Time Pad (Page 120)
    - DES/Lucifer (Page ???)
    - Diffe-Hellman-Merkle Key Exchange (Page 267)
*/

package ciphers

import (
	"crypto/rand"
	"errors"
	// "fmt"
	"math"
	"math/big"
)

/* The genius of the Vigenere cipher is that it employs multiple cipher alphabets, of which are in use is determined by a key. The
power in this is that a single character could be enciphered as any other character any number of times (depending on the
complexity of the key), which made simple cryptanalysis impossible. Of course, it still has weaknesses, and has been throughouly
broken, but it still remains the basis of the first truly unbreakable cipher

Traditionally, to encrypt/decrypt a Vigenere cipher, you'd use a Vigenere square:

= + A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
+ + + + + + + + + + + + + + + + + + + + + + + + + + + +
A + B C D E F G H I J K L M N O P Q R S T U V W X Y Z A
B + C D E F G H I J K L M N O P Q R S T U V W X Y Z A B
C + D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
D + E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
E + F G H I J K L M N O P Q R S T U V W X Y Z A B C D E
F + G H I J K L M N O P Q R S T U V W X Y Z A B C D E F
G + H I J K L M N O P Q R S T U V W X Y Z A B C D E F G
H + I J K L M N O P Q R S T U V W X Y Z A B C D E F G H
I + J K L M N O P Q R S T U V W X Y Z A B C D E F G H I
J + K L M N O P Q R S T U V W X Y Z A B C D E F G H I J
K + L M N O P Q R S T U V W X Y Z A B C D E F G H I J K
L + M N O P Q R S T U V W X Y Z A B C D E F G H I J K L
M + N O P Q R S T U V W X Y Z A B C D E F G H I J K L M
N + O P Q R S T U V W X Y Z A B C D E F G H I J K L M N
O + P Q R S T U V W X Y Z A B C D E F G H I J K L M N O
P + Q R S T U V W X Y Z A B C D E F G H I J K L M N O P
Q + R S T U V W X Y Z A B C D E F G H I J K L M N O P Q
R + S T U V W X Y Z A B C D E F G H I J K L M N O P Q R
S + T U V W X Y Z A B C D E F G H I J K L M N O P Q R S
T + U V W X Y Z A B C D E F G H I J K L M N O P Q R S T
U + V W X Y Z A B C D E F G H I J K L M N O P Q R S T U
V + W X Y Z A B C D E F G H I J K L M N O P Q R S T U V
W + X Y Z A B C D E F G H I J K L M N O P Q R S T U V W
X + Y Z A B C D E F G H I J K L M N O P Q R S T U V W X
Y + Z A B C D E F G H I J K L M N O P Q R S T U V W X Y
Z + A B C D E F G H I J K L M N O P Q R S T U V W X Y Z

You'd find the intersection between a plaintext and keytext (or ciphertext and keytext) to get the resultant letter. Repeating over
the whole text would get you the result

    Plaintext:  THYSECRETISTHYPRISONERIFTHOULETITGOTHOUARTAPRISONERTOIT
    Keytext:    ANDYETEMANCIPATEDITMUSTBEANDYETEMANCIPATEDITMUSTBEANDYE
    Ciphertext: UVCRJWWRUWVCXZJWMBIAZKCHYICYKJNNGHCWQEVUWXJJEDLIPJSHSHY

Now, instead of dealing with this in a 2d array, I realized there's a trick: The i'th character of the ciphertext
is equal to (Ti + Ki + 1) % 26, where Ti is the i'th letter of the text, Ki is the i'th letter of the keytext, and where
0 = 'A' and 25 = 'Z'. All of the extra fluff you'll see in the actual implementation is just dealing with character encoding.
Decryption is also easy, given that you just do the steps backwards

*/

func VigenereEncrypt(plaintext, keytext string) (string, error) {
    if(len(plaintext) <= 0 || len(keytext) <= 0) {return "", errors.New("given empty string")}
    plaintext, err := stripnonalpha(plaintext)
    if len(plaintext) <= 0 || err != nil {return "", errors.New("could not strip non-alphanumeric characters from text")}

    var res string

    for i := 0; i < len(plaintext); i++ {
        res += string(((([]rune(plaintext)[i] - 'A') + ([]rune(keytext)[i%len(keytext)] - 'A') + 1) % ('Z' - 'A' + 1)) + 'A')
    }

    return res, nil
}

func VigenereDecrypt(ciphertext, keytext string) (string, error) {
    if(len(ciphertext) <= 0 || len(keytext) <= 0) {return "", errors.New("given empty string")}
    ciphertext, err := stripnonalpha(ciphertext)
    if len(ciphertext) <= 0 || err != nil {return "", errors.New("could not strip non-alphanumeric characters from text")}

    var res string

    for i, inter := 0, rune(0); i < len(ciphertext); i++ {
        inter = ([]rune(ciphertext)[i] - 'A') - ([]rune(keytext)[i%len(keytext)] - 'A') - 1
        if inter < 0 {inter += rune(ROMANWIDTH)}
        res += string(inter + 'A')
    }

    return res, nil
}

/* The One Time Pad is the first truly unbreakable encryption scheme to be created, and relies on the Vigenere cipher. It is
essentially a Vigenere Cipher with a random key that's as long as the plaintext. The keys would be distributed to sender and
recipiant beforehand, then used to encrypt/decrypt a message. Once they were used, they were to be burned/destroyed as to 
prevent the issue of reuse weaking the key. */

func OTPEncrypt(plaintext string) (string, []rune, error) {
    if len(plaintext) <= 0 {return "", nil, errors.New("given empty string")}
    var ciphertext string
    var key []rune
    
    randplacate := big.NewInt(int64(ROMANWIDTH))
    for i := 0; i < len(plaintext); i++ {
        num, err := rand.Int(rand.Reader, randplacate)
        if err != nil {return "", nil, errors.New("could not generate random number")}
        key = append(key, rune(num.Int64() + 'A'))
    }

    ciphertext, err := VigenereEncrypt(plaintext, string(key))
    return ciphertext, key, err
}

func OTPDecrypt(ciphertext string, key []rune) (string, error) {
    if len(ciphertext) <= 0 || len(key) <= 0 {return "", errors.New("given empty string or key")}
    return VigenereDecrypt(ciphertext, string(key))
}


/* The Diffie-Hellman(-Merkle) Key Exchange was a huge breakthrough in cryptography, as it solved the problem of exchanging a key.
This has been a concern since the dawn of cryptography as a science, and until the DHM Group had this breakthrough, it was
considered an unfortunate and insurpassable hurdle that would simply need to be worked around. Yet, with the key exchange, the
previously costly process of manually giving someone a key in person was now completely unnecessary

The trick that the DHM Group discovered, Hellman specifically, is that it was possible to use modular arithmetic to publicly share
some numbers used in the process of sharing a key without giving up the information necessary to create the key due to the one-way
nature of the modulus operation. This meant that, much like mixing paint, once the number was generated it was practically 
impossible to generate it from the end product. All that needed to happen for the key exchange to be secure is the use of
sufficiently large numbers so that the amount of time someone would need to spend to regenrate your key would be cost prohibitive
or functionally impossible - possible, but so hard that with our current technological capibilities it would take many times the
lifespan of the universe to get the key

The DHM Key Exchange is still used today, funnily enough (well so is RSA so that's not too crazy), but in slightly different
variations than the original modular arithmetic. For example, ECDHE - Eliptic Curve Diffe-Hellman(-Merkle) Exchange - uses
properties of eliptic curves over finite fields to recreate the mod properties of the standard DHE algorithm. Frankly, I do not
understand the eliptic curve variant, so I will not implement it (as of now, I may in the future) */

func DHMkeStep1(y, p *big.Int) (*big.Int, *big.Int, error) {
    if y == nil || p == nil {return nil, nil, errors.New("got nil y or p")}
    // if p.BitLen() < 2048 {return nil, nil, errors.New("p is too small of a number. Should be at least 2048 bits long. Got: " + fmt.Sprint(p.BitLen()))}
    
    secret, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
    if err != nil {return nil, nil, errors.New("could not generate secret number")}
    
    res := big.NewInt(0).Exp(y, secret, p)
    // Note: Because this operation is not time constant its use makes this function vulnerable to side-channel attacks

    return secret, res, nil
}

func DHMkeStep2(shared, secret, p *big.Int) (*big.Int, error) {
    if shared == nil || secret == nil || p == nil {return nil, errors.New("given nil big.Int pointer")}
    return big.NewInt(0).Exp(shared, secret, p), nil    
    // Again, still vulnerable to side-channel attacks
}

// TODO: Make some function that guarantees that p is prime, and that y is a primitive root 
// modulo of p. 


/* RSA, short for Rivest Shamir Adleman, was the first (publicly available) asymmetric cryptosystem to be invented, and is still 
in common use today. While no longer the golden standard, the product of their research was arguably THE start of modern 
cryptography, where computers and cryptographers rule, and where cryptanalysits are left with very very little to work with. 
Asymmetric key cryptography solved the problem that Diffie, Hellman, and Merkle couldn't: the necessity of the communication 
partner to be online. If Alice and Bob want to communicate via a shared key, communicated via a DHM key exchange, they must either
both be online at the same time or must deal with a potentially large latency to create a shared key. Asymmetric keys don't have 
this problem, as anyone can encrypt anything via your public key and send it to you, and you can decrypt it at any time with your
private key. Asymmetric keys have other fun functions, like signing, where you "encrypt" something with your private key so that
people can verify that your communication is actually from you via your public key

And now I have to implement it because it's in the book */

