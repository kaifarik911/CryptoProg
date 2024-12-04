#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1 // Включаем поддержку слабых алгоритмов
#include <iostream>
#include <fstream>
#include <cryptopp/md4.h>
#include <cryptopp/hex.h>

using namespace CryptoPP; // Пространство имен Crypto++
using namespace std;

// Функция для вычисления хэша MD4 из файла
string calculateMD4(const string& filename) {
    Weak::MD4 hash; // Используем Weak::MD4

    // Открываем файл для бинарного чтения
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Ошибка открытия файла" << endl;
        exit(EXIT_FAILURE);
    }

    // Устанавливаем буфер для чтения файла
    const size_t bufferSize = 8192;
    CryptoPP::byte buffer[bufferSize]; // Явно указываем CryptoPP::byte

    // Инициализация хэша
    while (file.read(reinterpret_cast<char*>(buffer), bufferSize)) {
        hash.Update(buffer, file.gcount());
    }
    // Обработка оставшихся данных (если файл меньше bufferSize)
    if (file.gcount() > 0) {
        hash.Update(buffer, file.gcount());
    }

    // Завершение вычисления хэша
    file.close();
    CryptoPP::byte hashResult[Weak::MD4::DIGESTSIZE]; // Явно указываем CryptoPP::byte
    hash.Final(hashResult);

    // Преобразование бинарного хэша в строку шестнадцатеричных цифр
    string hexResult;
    StringSource(hashResult, sizeof(hashResult), true,
                 new HexEncoder(new StringSink(hexResult)));

    return hexResult;
}

int main() {
    // Замените "example.txt" на имя вашего файла
    const string filename = "text.txt";

    string hashResult = calculateMD4(filename);

    cout << "MD4: " << hashResult << endl;

    return 0;
}
