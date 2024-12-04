#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;
using namespace std;

// Генерация ключа из пароля
SecByteBlock generateKeyFromPassword(const string& password) {
    SecByteBlock key(AES::MAX_KEYLENGTH);
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
    pbkdf2.DeriveKey(
        key, key.size(), 0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        1000 // количество итераций
    );
    return key;
}

// Шифрование файла
void encryptFile(const string& inputFile, const string& outputFile, const string& password) {
    SecByteBlock key = generateKeyFromPassword(password);
    SecByteBlock iv(AES::BLOCKSIZE);

    AutoSeededRandomPool prng;
    prng.GenerateBlock(iv, iv.size());

    ofstream encryptedFile(outputFile, ios::binary);

    // Записываем IV в начало файла
    encryptedFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, key.size(), iv);

    FileSource(inputFile.c_str(), true,
               new StreamTransformationFilter(encryptor,
               new FileSink(encryptedFile)));
}

// Расшифровка файла
void decryptFile(const string& inputFile, const string& outputFile, const string& password) {
    SecByteBlock key = generateKeyFromPassword(password);
    SecByteBlock iv(AES::BLOCKSIZE);

    ifstream encryptedFile(inputFile, ios::binary);

    // Считываем IV из начала файла
    encryptedFile.read(reinterpret_cast<char*>(iv.data()), iv.size());

    CBC_Mode<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key, key.size(), iv);

    FileSource(encryptedFile, true,
               new StreamTransformationFilter(decryptor,
               new FileSink(outputFile.c_str())));
}

int main() {
    std::string mode;
    std::string inputFile;
    std::string outputFile;
    std::string password;

    std::cout << "Enter mode (1 - encrypt / 2 - decrypt): ";
    std::cin >> mode;

    std::cout << "Enter input file: ";
    std::cin >> inputFile;

    std::cout << "Enter output file: ";
    std::cin >> outputFile;

    std::cout << "Enter password: ";
    std::cin >> password;

    if (mode == "1") {
        encryptFile(inputFile, outputFile, password);
        std::cout << "File encrypted successfully." << std::endl;
    } else if (mode == "2") {
        decryptFile(inputFile, outputFile, password);
        std::cout << "File decrypted successfully." << std::endl;
    } else {
        std::cerr << "Invalid mode. Please enter '1' for encrypt or '2' for decrypt." << std::endl;
        return 1;
    }

    return 0;
}
