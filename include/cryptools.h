#ifndef CRYPTOOLS_H
#define CRYPTOOLS_H

#include <string>
#include <iostream>
#include <vector>

#include "zedwood/sha256.h"
#include "zedwood/sha512.h"

class Types
{
public:
    enum Text {
        Numbers,
        LowercaseAlphabet,
        UppercaseAlphabet,
        Alphabet,
        AlphaNum,
        Base64,
        Unicode
    };
    enum Case {
        Lowercase = LowercaseAlphabet,
        Uppercase = UppercaseAlphabet
    };
};

class CrypTools: public std::string
{
public:
    explicit CrypTools(std::string text);
    explicit CrypTools();
//========================================================================
//                        Static public functions
//========================================================================
    static std::string toBase64  (std::string plaintext);
    static std::string fromBase64(std::string cipher   );
//========================================================================
    static std::string caesarEncrypt(int shift, std::string plaintext, Types::Text type = Types::Alphabet);
    static std::string caesarDecrypt(int shift, std::string cipher   , Types::Text type = Types::Alphabet);
//========================================================================
    static std::string rot13(std::string input, Types::Case type = Types::Lowercase);
//========================================================================
    static std::string vigenereEncrypt(std::string plaintext, std::string key);
    static std::string vigenereDecrypt(std::string cipher   , std::string key);
//========================================================================
    static std::string XOR(std::string input, std::string key);
//========================================================================
    static std::string safeVigenereEncrypt(std::string plaintext, std::string key);
    static std::string safeVigenereDecrypt(std::string cipher   , std::string key);
//========================================================================
    static std::string vigenereAlphaOnly(std::string plaintext, std::string key, int way) {
        unsigned int ilen = plaintext.length(), klen = key.length();
        for (unsigned int i=0; i<ilen; ++i) {
            plaintext[i] = (plaintext[i]-97+(key[i%klen]-97)*way)%26+97;
        }
        return plaintext;
    }
//========================================================================
    bool isNumber() const;
    bool isAlphabet() const;
    bool isAlphaNumerical() const;
    CrypTools binValueAt(unsigned int index) const;
    bool contains(char character) const;

    static unsigned int indexOfFirst(std::string array, char character);
    unsigned int indexOfFirst(char character) const;

    static std::string decToBin(unsigned int value);
//========================================================================
//                     Non-static public functions
//========================================================================
    std::string toBase64() const;
    std::string fromBase64() const;
//========================================================================
    std::string caesarEncrypt(int shift, Types::Text type = Types::Alphabet) const;
    std::string caesarDecrypt(int shift, Types::Text type = Types::Alphabet) const;
//========================================================================
    std::string rot13(Types::Case type = Types::Lowercase) const;
//========================================================================
    std::string vigenereEncrypt(std::string key) const;
    std::string vigenereDecrypt(std::string key) const;
//========================================================================
    std::string XOR(std::string key) const;
//========================================================================
    std::string safeVigenereEncrypt(std::string key) const;
    std::string safeVigenereDecrypt(std::string key) const;
//========================================================================

    static std::string generateKey(std::string input_key, unsigned int goal);

    static bool containsWhat(const std::string text, char character);
private:
    static long fromBin(long n);

    static std::string stringShift(std::string text, int shift = 0);
    static std::string stringShiftInArray(std::string array, std::string text, int shift = 0);
    static std::string toBin(int n);
    static std::string valueInRange(std::string text, unsigned int lower, unsigned int upper);
    static std::string base64Encrypt(std::string plaintext);
    static std::string base64Decrypt(std::string cipher);
    static std::string XORCipher(std::string input, std::string key);

    static std::string vigenereShifts(std::string input, std::string key, int goal = 0);//goal: 1 is encrypt, -1 is decrypt
    static std::string charMultiple(int times, char character);

};

#endif // CRYPTOOLS_H
