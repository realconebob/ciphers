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
*/

package ciphers

import (
	"crypto/rand"
	"errors"
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