#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include "resource.h"

#include "include/cryptools.h"
#include "include/zedwood/md5.h"
#include "include/zedwood/sha512.h"

#define MCHAR 4096

HINSTANCE hInst;

bool cmdClean = true;
HWND HashesComboBox;

enum cryptions {
    CXOR,
    CROT13,
    CTOBASE64,
    CFROMBASE64,
    CTOCAESAR,
    CFROMCAESAR,
    CTOVIGENERE,
    CFROMVIGENERE,
    CTOSAFEVIGE,
    CFROMSAFEVIGE
};

bool vige_alpha_checked = false;

void fillHashComboBox();

void ProcessHash(HWND parent, int input, int output);
void ProcessKeyExtension(HWND parent, int input, int key, int output);
void ProcessEncryption(cryptions method, HWND parent, int input,int key, int output);
void ProcessEncryptionS(cryptions method1, cryptions method2, HWND parent, int input, int key, int output);
std::string ProcessText(std::string text, std::string dict);

void stringSwitch(std::string & inputStd, std::string & keyStd, char * keySTR, cryptions method);

BOOL CALLBACK DlgMain(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_INITDIALOG:
    {
        HashesComboBox = GetDlgItem(hwndDlg, ID_HASHES_COMBOBOX);
        fillHashComboBox();
    }
    return TRUE;

    case WM_CLOSE:
    {
        EndDialog(hwndDlg, 0);
    }
    return TRUE;

    case WM_COMMAND:
    {
        switch(LOWORD(wParam))
        {
            //Ciphers buttons
        case ID_CIPHERS_DLGXOR_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_XOR), NULL, (DLGPROC)DlgMain);
            break;
        case ID_CIPHERS_DLGROT13_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_ROT13), NULL, (DLGPROC)DlgMain);
            break;
        case ID_CIPHERS_DLGB64_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_B64), NULL, (DLGPROC)DlgMain);
            break;
        case ID_CIPHERS_CAESAR_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_CAESAR), NULL, (DLGPROC)DlgMain);
            break;
        case ID_CIPHERS_VIGENERE_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_VIGENERE), NULL, (DLGPROC)DlgMain);
            break;
        case ID_CIPHERS_SAVEVIGE_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_SAFEVIGE), NULL, (DLGPROC)DlgMain);
            break;

            //Others buttons
        case ID_OTHERS_HASHES_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_HASHES), NULL, (DLGPROC)DlgMain);
            break;
        case ID_OTHERS_SVB64_BUTTON:
            DialogBox(hInst, MAKEINTRESOURCE(DLG_SVB64), NULL, (DLGPROC)DlgMain);
            break;

            //Check boxes handling
        case ID_VIGENERE_ALPHABET_CHECK:
            if (SendDlgItemMessage(hwndDlg, ID_VIGENERE_ALPHABET_CHECK, BM_GETCHECK, 0, 0))
                vige_alpha_checked = true;
            else
                vige_alpha_checked = false;
            break;

            //Combo box handling
        case ID_HASHES_COMBOBOX:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                ProcessHash(hwndDlg, ID_HASHES_INPUT_TEXT, ID_HASHES_OUTPUT_TEXT);
            }
            break;

            //Hash auto update
        case ID_HASHES_INPUT_TEXT:
            if (HIWORD(wParam) == EN_CHANGE)
                ProcessHash(hwndDlg, ID_HASHES_INPUT_TEXT, ID_HASHES_OUTPUT_TEXT);
            break;

        case ID_SAFEVIGE_INPUT_TEXT:
        case ID_SAFEVIGE_KEY_LINE:
            if (HIWORD(wParam) == EN_CHANGE)
                ProcessKeyExtension(hwndDlg, ID_SAFEVIGE_INPUT_TEXT, ID_SAFEVIGE_KEY_LINE, ID_SAFEVIGE_LONGKEY_TEXT);
            break;

            //Dialogs buttons
        case ID_XOR_APPLY_PUSHBUTTON:
            ProcessEncryption(CXOR, hwndDlg, ID_XOR_INPUT_TEXT, ID_XOR_KEY_LINE, ID_XOR_OUTPUT_TEXT);
            break;
        case ID_ROT13_APPLY_PUSHBUTTON:
            ProcessEncryption(CROT13, hwndDlg, ID_ROT13_INPUT_TEXT, 0, ID_ROT13_OUTPUT_TEXT);
            break;
        case ID_BASE64_ENCODE_BUTTON:
            ProcessEncryption(CTOBASE64, hwndDlg, ID_BASE64_INPUT_TEXT, 0, ID_BASE64_OUTPUT_TEXT);
            break;
        case ID_BASE64_DECODE_BUTTON:
            ProcessEncryption(CFROMBASE64, hwndDlg, ID_BASE64_INPUT_TEXT, 0, ID_BASE64_OUTPUT_TEXT);
            break;
        case ID_CAESAR_ENCRYPT_BUTTON:
            ProcessEncryption(CTOCAESAR, hwndDlg, ID_CAESAR_INPUT_TEXT, ID_CAESAR_KEY_LINE, ID_CAESAR_OUTPUT_TEXT);
            break;
        case ID_CAESAR_DECRYPT_BUTTON:
            ProcessEncryption(CFROMCAESAR, hwndDlg, ID_CAESAR_INPUT_TEXT, ID_CAESAR_KEY_LINE, ID_CAESAR_OUTPUT_TEXT);
            break;
        case ID_VIGENERE_ENCRYPT_BUTTON:
            ProcessEncryption(CTOVIGENERE, hwndDlg, ID_VIGENERE_INPUT_TEXT, ID_VIGENERE_KEY_LINE, ID_VIGENERE_OUTPUT_TEXT);
            break;
        case ID_VIGENERE_DECRYPT_BUTTON:
            ProcessEncryption(CFROMVIGENERE, hwndDlg, ID_VIGENERE_INPUT_TEXT, ID_VIGENERE_KEY_LINE, ID_VIGENERE_OUTPUT_TEXT);
            break;
        case ID_SAFEVIGE_ENCRYPT_BUTTON:
            ProcessEncryption(CTOSAFEVIGE, hwndDlg, ID_SAFEVIGE_INPUT_TEXT, ID_SAFEVIGE_LONGKEY_TEXT, ID_SAFEVIGE_OUTPUT_TEXT);
            break;
        case ID_SAFEVIGE_DECRYPT_BUTTON:
            ProcessEncryption(CFROMSAFEVIGE, hwndDlg, ID_SAFEVIGE_INPUT_TEXT, ID_SAFEVIGE_LONGKEY_TEXT, ID_SAFEVIGE_OUTPUT_TEXT);
            break;

            //Multiple encryptions buttons
        case ID_SVB64_ENCRYPT_BUTTON:
            ProcessEncryptionS(CTOSAFEVIGE, CTOBASE64, hwndDlg, ID_SVB64_INPUT_TEXT, ID_SVB64_KEY_LINE, ID_SVB64_OUTPUT_TEXT);
            break;
        case ID_SVB64_DECRYPT_BUTTON:
            ProcessEncryptionS(CFROMBASE64, CFROMSAFEVIGE, hwndDlg, ID_SVB64_INPUT_TEXT, ID_SVB64_KEY_LINE, ID_SVB64_OUTPUT_TEXT);
            break;
        }
    }
    return TRUE;
    }
    return FALSE;
}


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    hInst=hInstance;
    InitCommonControls();
    return DialogBox(hInst, MAKEINTRESOURCE(DLG_MAIN), NULL, (DLGPROC)DlgMain);
}

void ProcessEncryption(cryptions method, HWND parent, int input, int key, int output)
{
    if (cmdClean == false)
        std::cout << "--------------------------------------\r\n\r\n";

    char inputSTR[MCHAR], keySTR[MCHAR];

    GetDlgItemText(parent, input, inputSTR, MCHAR);

    if (key != 0)
        GetDlgItemText(parent, key, keySTR, MCHAR);

    std::string inputStd(inputSTR), keyStd(keySTR), outputStd;

    std::cout << "================\r\nStarting encryption\r\n================" << std::endl;

    std::cout << "Input STD: " << inputStd << std::endl;

    if (key != 0)
        std::cout << "Key STD: " << keyStd << std::endl;

    std::cout << std::endl;

    stringSwitch(inputStd, keyStd, keySTR, method);

    std::cout << std::endl << "Output STD: " << inputStd << std::endl << std::endl;

    const char* outputSTR = inputStd.c_str();

    SetDlgItemText(parent, output, outputSTR);

    cmdClean = false;

    return;
}

std::string ProcessText(std::string text, std::string dict)
{
    std::string output;
    unsigned int textlen = text.length();
    for (unsigned int i=0; i<textlen; ++i) {
        if (CrypTools::containsWhat(dict, text[i]) == true) {
            output += text[i];
        }
    }
    return output;
}

void fillHashComboBox()
{
    SendMessage(HashesComboBox, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>((LPCTSTR)"MD5"));
    SendMessage(HashesComboBox, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>((LPCTSTR)"SHA256"));
    SendMessage(HashesComboBox, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>((LPCTSTR)"SHA512"));
    SendMessage(HashesComboBox, CB_SELECTSTRING, 0, reinterpret_cast<LPARAM>((LPCTSTR)"SHA256"));
}

void ProcessHash(HWND parent, int input, int output)
{
    char INCHAR[MCHAR];
    GetDlgItemText(parent, input, INCHAR, MCHAR);

    unsigned int currentIndex =
    SendMessage(HashesComboBox, CB_GETCURSEL, 0, 0);

    std::string INSTD(INCHAR);
    std::string OUTSTD;

    switch (currentIndex)
    {
    case 0:
        OUTSTD = md5(INSTD);
        break;
    case 1:
        OUTSTD = sha256(INSTD);
        break;
    case 2:
        OUTSTD = sha512(INSTD);
        break;
    default:
        OUTSTD = "Invalid selection";
        break;
    }

    SetDlgItemText(parent, output, OUTSTD.c_str());
}

void ProcessKeyExtension(HWND parent, int input, int key, int output)
{
    char INCHAR[MCHAR], KEYCHAR[MCHAR];

    GetDlgItemText(parent, input, INCHAR, MCHAR);
    GetDlgItemText(parent, key, KEYCHAR, MCHAR);

    std::string INSTD(INCHAR), KEYSTD(KEYCHAR);

    std::string OUTSTD = CrypTools::generateKey(KEYSTD, INSTD.length());

    SetDlgItemText(parent, output, OUTSTD.c_str());
}

void ProcessEncryptionS(cryptions method1, cryptions method2, HWND parent, int input, int key, int output)
{
    if (cmdClean == false)
        std::cout << "--------------------------------------\r\n\r\n";

    char inputSTR[MCHAR], keySTR[MCHAR];

    GetDlgItemText(parent, input, inputSTR, MCHAR);

    if (key != 0)
        GetDlgItemText(parent, key, keySTR, MCHAR);

    std::string inputStd(inputSTR), keyStd(keySTR);

    std::cout << "================\r\nStarting encryption\r\n================" << std::endl;

    std::cout << "Input STD: " << inputStd << std::endl;

    if (key != 0)
        std::cout << "Key STD: " << keyStd << std::endl;

    std::cout << std::endl;

    stringSwitch(inputStd, keyStd, keySTR, method1);
    stringSwitch(inputStd, keyStd, keySTR, method2);

    std::cout << std::endl << "Output STD: " << inputStd << std::endl << std::endl;

    const char* outputSTR = inputStd.c_str();

    SetDlgItemText(parent, output, outputSTR);

    cmdClean = false;

    return;
}

void stringSwitch(std::string & inputStd, std::string & keyStd, char * keySTR, cryptions method)
{
    switch (method)
    {
    case CXOR:
        std::cout << "================\r\nApplying XOR crypt\r\n================" << std::endl;
        inputStd = CrypTools::XOR(inputStd, keyStd);
        break;

    case CROT13:
        std::cout << "================\r\nProcessing text\r\n================" << std::endl;
        inputStd = ProcessText(inputStd, "abcdefghijklmnopqrstuvwxyz");
        std::cout << "Done" << std::endl;
        std::cout << "================\r\nApplying ROT13 crypt\r\n================" << std::endl;
        inputStd = CrypTools::rot13(inputStd);
        break;

    case CTOBASE64:
        std::cout << "================\r\nEncoding to base64\r\n================" << std::endl;
        inputStd = CrypTools::toBase64(inputStd);
        break;

    case CFROMBASE64:
        std::cout << "================\r\nDecoding from base64\r\n================" << std::endl;
        inputStd = CrypTools::fromBase64(inputStd);
        break;

    case CTOCAESAR:
        std::cout << "================\r\nProcessing text\r\n================" << std::endl;
        inputStd = ProcessText(inputStd, "abcdefghijklmnopqrstuvwxyz");
        std::cout << "Done" << std::endl;
        std::cout << "================\r\nApplying Caesar encryption\r\n================" << std::endl;
        inputStd = CrypTools::caesarEncrypt(atoi(keySTR), inputStd, Types::LowercaseAlphabet);
        break;

    case CFROMCAESAR:
        std::cout << "================\r\nProcessing text\r\n================" << std::endl;
        inputStd = ProcessText(inputStd, "abcdefghijklmnopqrstuvwxyz");
        std::cout << "Done" << std::endl;
        std::cout << "================\r\nApplying Caesar decryption\r\n================" << std::endl;
        inputStd = CrypTools::caesarEncrypt(26-atoi(keySTR), inputStd, Types::LowercaseAlphabet);
        break;

    case CTOVIGENERE:
        if (vige_alpha_checked == true) {
            std::cout << "================\r\nProcessing text\r\n================" << std::endl;
            inputStd = ProcessText(inputStd, "abcdefghijklmnopqrstuvwxyz");
            std::cout << "Done" << std::endl;
            std::cout << "================\r\nApplying Vigenère encryption\r\n================" << std::endl;
            inputStd = CrypTools::vigenereAlphaOnly(inputStd, keyStd, 1);
        }
        else {
            std::cout << "================\r\nApplying Vigenère encryption\r\n================" << std::endl;
            inputStd = CrypTools::vigenereEncrypt(inputStd, keyStd);
        }
        break;

    case CFROMVIGENERE:
        if (vige_alpha_checked == true) {
            std::cout << "================\r\nProcessing text\r\n================" << std::endl;
            inputStd = ProcessText(inputStd, "abcdefghijklmnopqrstuvwxyz");
            std::cout << "Done" << std::endl;
            std::cout << "================\r\nApplying Vigenère decryption\r\n================" << std::endl;
            inputStd = CrypTools::vigenereAlphaOnly(inputStd, keyStd, -1);
        }
        else {
            std::cout << "================\r\nApplying Vigenère decryption\r\n================" << std::endl;
            inputStd = CrypTools::vigenereDecrypt(inputStd, keyStd);
        }
        break;

    case CTOSAFEVIGE:
        std::cout << "================\r\nApplying safe Vigenère encryption\r\n================" << std::endl;
        inputStd = CrypTools::vigenereEncrypt(inputStd, keyStd);
        break;

    case CFROMSAFEVIGE:
        std::cout << "================\r\nApplying safe Vigenère decryption\r\n================" << std::endl;
        inputStd = CrypTools::vigenereDecrypt(inputStd, keyStd);
        break;
    }
}

