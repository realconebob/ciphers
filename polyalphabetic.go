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
*/

package ciphers

import (
	"errors"
)

func VigenereEncrypt(plaintext, keytext string) (string, error) {
    /** The traditional Vigenere cipher employs a Vigenere square, which looks like this:

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

        To encipher or decipher text, you'd take the text and map a key to it. For example:

        Plaintext:  THYSECRETISTHYPRISONERIFTHOULETITGOTHOUARTAPRISONERTOIT
        Keytext:    ANDYETEMANCIPATEDITMUSTBEANDYETEMANCIPATEDITMUSTBEANDYE

        Then, you'd find the intersections between the plaintext and keytext. Plaintext is mapped to X, keytext to Y

        Ciphertext: UVCRJWWRUWVCXZJWMBIAZKCHYICYKJNNGHCWQEVUWXJJEDLIPJSHSHY

        Now, instead of dealing with this in a 2d array, I realized there's a trick: The i'th character of the ciphertext
        is equal to (Pi + Ti + 1) % 26. All of the extra fluff is dealing with character encoding. That +1 initial offset
        could be any number, but for ease of implementation I will leave it out
    */

    if(len(plaintext) <= 0 || len(keytext) <= 0) {return "", errors.New("given empty string")}

    var res string

    for i := 0; i < len(plaintext); i++ {
        res += string(((([]rune(plaintext)[i] - 'A') + ([]rune(keytext)[i%len(keytext)] - 'A') + 1) % ('Z' - 'A' + 1)) + 'A')
    }

    return res, nil
}

func VigenereDecrypt(ciphertext, keytext string) (string, error) {
    if(len(ciphertext) <= 0 || len(keytext) <= 0) {return "", errors.New("given empty string")}

    var res string

    for i, inter := 0, rune(0); i < len(ciphertext); i++ {
        inter = ([]rune(ciphertext)[i] - 'A') - ([]rune(keytext)[i%len(keytext)] - 'A') - 1
        if inter < 0 {inter += 26}
        res += string(inter + 'A')
    }

    return res, nil
}