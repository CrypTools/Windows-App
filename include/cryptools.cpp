#include "cryptools.h"

#include <math.h>

std::string base10Numbers = "0123456789",
lowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz",
uppercaseAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
alphabet = lowercaseAlphabet + uppercaseAlphabet;

CrypTools::CrypTools(std::string text):
    std::string(text)
{

}

CrypTools::CrypTools():
    std::string()
{}

bool CrypTools::isNumber() const
{
    std::string temp = *this;
    for (unsigned int i=0; i<temp.length(); ++i)
        if (containsWhat(base10Numbers, temp[i]) == false)
            return false;
    return true;
}

bool CrypTools::isAlphabet() const
{
    std::string temp = *this;
    for (unsigned int i=0; i<temp.length(); ++i)
        if (containsWhat(alphabet, temp[i]) == false)
            return false;
    return true;
}

bool CrypTools::isAlphaNumerical() const
{
    std::string temp = *this;
    for (unsigned int i=0; i<temp.length(); ++i)
        if (containsWhat(alphabet+base10Numbers, temp[i]) == false)
            return false;
    return true;
}

CrypTools CrypTools::binValueAt(unsigned int index) const
{
    return CrypTools(toBin((*this)[index]));
}

bool CrypTools::contains(char character) const
{
    return containsWhat(*this, character);
}

bool CrypTools::containsWhat(const std::string text, char character)
{
    for (unsigned int i=0; i<text.length(); ++i)
        if (text[i] == character)
            return true;
    return false;
}

std::string CrypTools::toBin(int n)
{
    std::string r;
    while(n!=0) {r=(n%2==0 ?"0":"1")+r; n/=2;}
    return r;
}

std::string CrypTools::valueInRange(std::string text, unsigned int lower, unsigned int upper)
{
    std::string r;
    if (upper == 0)
        upper = text.length();
    for (unsigned int i=lower; i < upper; i++)
        r += text[i];
    return r;
}

std::string CrypTools::charMultiple(int times, char character)
{
    std::string r;
    for (int i=0; i<times; ++i){
        r[i] = character;
    }
    return r;
}

long CrypTools::fromBin(long n)
{
    long factor = 1;
    long total = 0;

    while (n != 0)
    {
        total += (n%10) * factor;
        n /= 10;
        factor *= 2;
    }

    return total;
}

unsigned int CrypTools::indexOfFirst(std::string array, char character)
{
    unsigned int i;
    for (i=0; i<array.length(); ++i)
        if (array[i] == character)
            return i;
    throw;
}

unsigned int CrypTools::indexOfFirst(char character) const
{
    unsigned int i;
    for (i=0; i<this->length(); ++i)
        if ((*this)[i] == character)
            return i;
    throw;
}

//========================================================================
//                        Public useful functions
//========================================================================

std::string CrypTools::decToBin(unsigned int value)
{
    return toBin(value);
}

//========================================================================
//                    Public Base64 encryption functions
//========================================================================

std::string CrypTools::toBase64() const
{
    return base64Encrypt(*this);
}

std::string CrypTools::toBase64(std::string plaintext)
{
    return base64Encrypt(plaintext);
}

//========================================================================
//                    Public Base64 decryption functions
//========================================================================

std::string CrypTools::fromBase64() const
{
    return base64Decrypt(*this);
}

std::string CrypTools::fromBase64(std::string cipher)
{
    return base64Decrypt(cipher);
}

//========================================================================
//                       Private Base64 functions
//========================================================================

std::string CrypTools::base64Encrypt(std::string plaintext)
{
    std::string out;

    int val=0, valb=-6;
    for (unsigned char c : plaintext) {
        val = (val<<8) + c;
        valb += 8;
        while (valb>=0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val>>valb)&0x3F]);
            valb-=6;
        }
    }
    if (valb>-6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val<<8)>>(valb+8))&0x3F]);
    while (out.size()%4) out.push_back('=');
    return out;
}

std::string CrypTools::base64Decrypt(std::string cipher)
{
    std::string out;

    std::vector<int> T(256,-1);
    for (int i=0; i<64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val=0, valb=-8;
    for (unsigned char c : cipher) {
        if (T[c] == -1) break;
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(char((val>>valb)&0xFF));
            valb-=8;
        }
    }
    return out;
}

//========================================================================
//                       Public Vigenere functions
//========================================================================

//! Static

//! Classic

std::string CrypTools::vigenereEncrypt(std::string plaintext, std::string key)
{
    return vigenereShifts(plaintext, key, 1);
}

std::string CrypTools::vigenereDecrypt(std::string cipher, std::string key)
{
    return vigenereShifts(cipher, key, -1);
}

//! Safe

std::string CrypTools::safeVigenereEncrypt(std::string plaintext, std::string key)
{
    return vigenereShifts(plaintext, generateKey(key, plaintext.length()), 1);
}

std::string CrypTools::safeVigenereDecrypt(std::string cipher, std::string key)
{
    return vigenereShifts(cipher, generateKey(key, cipher.length()), -1);
}

//! Instance

//! Classic

std::string CrypTools::vigenereEncrypt(std::string key) const
{
    return vigenereShifts(*this, key, 1);
}

std::string CrypTools::vigenereDecrypt(std::string key) const
{
    return vigenereShifts(*this, key, -1);
}

//! Safe

std::string CrypTools::safeVigenereEncrypt(std::string key) const
{
    return vigenereShifts(*this, generateKey(key, this->length()), 1);
}

std::string CrypTools::safeVigenereDecrypt(std::string key) const
{
    return vigenereShifts(*this, generateKey(key, this->length()), -1);
}

//========================================================================
//                       Private Vigenere function
//========================================================================

std::string CrypTools::vigenereShifts(std::string input, std::string key, int goal)
{
    unsigned int keylen = key.length();
    for (unsigned int i=0; i<input.length(); ++i){
        input[i] = input[i] + (key[i%keylen] * goal);
    }
    return input;
}

//========================================================================
//                        Public Caesar functions
//========================================================================

std::string CrypTools::caesarEncrypt(int shift, std::string plaintext, Types::Text type)
{
    switch (type) {
    case Types::Unicode:
        plaintext = stringShift(plaintext, shift);
        break;
    case Types::Alphabet:
        plaintext = stringShiftInArray(alphabet, plaintext, shift);
        break;
    case Types::Base64:
        plaintext = stringShiftInArray(alphabet+base10Numbers+"+/", plaintext, shift);
        break;
    case Types::AlphaNum:
        plaintext = stringShiftInArray(alphabet+base10Numbers, plaintext, shift);
        break;
    case Types::LowercaseAlphabet:
        plaintext = stringShiftInArray(lowercaseAlphabet, plaintext, shift);
        break;
    case Types::UppercaseAlphabet:
        plaintext = stringShiftInArray(uppercaseAlphabet, plaintext, shift);
        break;
    case Types::Numbers:
        plaintext = stringShiftInArray(base10Numbers, plaintext, shift);
        break;
    default:
        plaintext = "";
        break;
    }
    return plaintext;
}

std::string CrypTools::caesarEncrypt(int shift, Types::Text type) const
{
    return caesarEncrypt(shift, *this, type);
}

std::string CrypTools::caesarDecrypt(int shift, std::string cipher, Types::Text type)
{
    return caesarEncrypt(-shift, cipher, type);
}

std::string CrypTools::caesarDecrypt(int shift, Types::Text type) const
{
    return caesarEncrypt(-shift, *this, type);
}

//========================================================================
//                           ROT13 functions
//========================================================================

std::string CrypTools::rot13(std::string input, Types::Case type)
{
    return caesarEncrypt(13, input, Types::Text(type));
}

std::string CrypTools::rot13(Types::Case type) const
{
    return caesarEncrypt(13, Types::Text(type));
}

//========================================================================
//                         Key extension
//========================================================================

std::string CrypTools::generateKey(std::string input_key, unsigned int goal)
{
    std::string key;
    unsigned int klen;

    key = sha512(input_key);

    while (key.length() < goal) {
        klen = key.length();
        key += sha512(valueInRange(key, 0, klen/2)) + sha512(valueInRange(key, klen/3, 0));
    }

    return key;
}

//========================================================================
//                         XOR functions
//========================================================================

std::string CrypTools::XORCipher(std::string input, std::string key)
{
    unsigned int keylen = key.length(), inputlen = input.length();
    for (unsigned int i=0; i<inputlen; ++i) {
        if (input[i] == key[i%keylen])
            input[i] = -1;
        else if (input[i] == -1)
            input[i] = key[i%keylen];
        else
        input[i] = input[i] ^ key[i%keylen];
    }
    return input;
}

std::string CrypTools::XOR(std::string input, std::string key)
{
    return XORCipher(input, key);
}

std::string CrypTools::XOR(std::string key) const
{
    return XORCipher(*this, key);
}

//========================================================================
//                   Various private string functions
//========================================================================

std::string CrypTools::stringShift(std::string text, int shift)
{
    for (unsigned int i=0; i<text.length(); ++i)
        text[i] += shift;
    return text;
}

std::string CrypTools::stringShiftInArray(std::string array, std::string text, int shift)
{
    for (unsigned int i=0; i<text.length(); ++i)
        text[i] = array[(indexOfFirst(array, text[i])+shift)%array.length()];
    return text;
}












