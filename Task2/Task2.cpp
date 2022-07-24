#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include <openssl/md5.h>
#include "openssl/sha.h"

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
{
    std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
    if (!fileStream.is_open())
    {
        throw std::runtime_error("Can not open file " + filePath);
    }

    buf.clear();
    buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

    fileStream.close();
}

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
    fileStream.write(&buf[0], buf.size());
    fileStream.close();
}

void PasswordToKey(const std::vector<unsigned char>& password)
{
    OpenSSL_add_all_digests();
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }

    const unsigned char* salt = NULL;
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), nullptr,
        &password[0],
        password.size(), 1, key, iv))
    {
        throw std::runtime_error("EVP_BytesToKey failed");
    }
}

void EncryptAes(const std::vector<unsigned char> plainText, std::vector<unsigned char>& chipherText)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> chipherTextBuf(plainText.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_EncryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &plainText[0], plainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_EncryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal error");
    }
    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    chipherText.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
}

bool DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& plainText)
{
    bool ret = 0;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    {
        throw std::runtime_error("EncryptInit error");
    }

    std::vector<unsigned char> chipherTextBuf(chipherText.size() + AES_BLOCK_SIZE);
    int chipherTextSize = 0;
    if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &chipherText[0], chipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encrypt error");
    }

    int lastPartLen = 0;
    if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    chipherTextSize += lastPartLen;
    chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

    plainText.swap(chipherTextBuf);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

void CalculateHash(unsigned char* data, size_t size)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(&hashTmp[0], &sha256);
}

void next(unsigned char* pass, int size)
{
    pass[0]++;
    for (size_t i = 0; i < size; ++i)
    {
        if (pass[i] == '9')
        {
            pass[i] = 'a';
            break;
        }
        else if (pass[i] == 'z')
        {
            pass[i] = '0';
            if (i + 1 < size)
            {
                pass[i + 1]++;
                break;
            }
        }
    }
}

void Decrypt()
{
    std::vector<unsigned char> chipherText;
    ReadFile("chipher_text_brute_force", chipherText);

    std::vector<unsigned char> hash;

    std::vector<unsigned char> hashText(chipherText.begin() + chipherText.size() - SHA256_DIGEST_LENGTH, chipherText.end());
    chipherText.erase(chipherText.begin() + chipherText.size() - SHA256_DIGEST_LENGTH, chipherText.end());

    std::vector<unsigned char> plainText;

    OpenSSL_add_all_digests();
    const EVP_MD* dgst = EVP_get_digestbyname("md5");
    if (!dgst)
    {
        throw std::runtime_error("no such digest");
    }
    std::vector<unsigned char> chipherTextBuf(chipherText.size() + AES_BLOCK_SIZE);

    const std::chrono::time_point<std::chrono::steady_clock> start =
        std::chrono::steady_clock::now();

    int passSize = 4;
    unsigned char* pass = new unsigned char[passSize + 1];
    pass[0] = '0';
    pass[1] = '0';
    pass[2] = '0';
    pass[3] = '0';
    pass[passSize] = '\0';

    /*for (pass[0] = '0'; pass[0] <= 'z'; ++pass[0])
    {
        for (pass[1] = '0'; pass[1] <= 'z'; ++pass[1])
        {
            for (pass[2] = '0'; pass[2] <= 'z'; ++pass[2])
            {
                for (pass[3] = '0'; pass[3] <= 'z'; ++pass[3])
                {
                */
    while (true)
    {
        next(pass, passSize);
        if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), nullptr, pass, passSize, 1, key, iv))
        {
            throw std::runtime_error("EVP_BytesToKey failed");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        {
            throw std::runtime_error("EncryptInit error");
        }


        int chipherTextSize = 0;
        if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &chipherText[0], chipherText.size())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Encrypt error");
        }

        int lastPartLen = 0;
        if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
            EVP_CIPHER_CTX_free(ctx);
            goto next;
        }
        chipherTextSize += lastPartLen;
        //chipherTextBuf.erase(chipherTextBuf.begin() + chipherTextSize, chipherTextBuf.end());

        //plainText.swap(chipherTextBuf);

        EVP_CIPHER_CTX_free(ctx);


        CalculateHash(&chipherTextBuf[0], chipherTextSize);
        if (hashTmp == hashText)
        {
            const auto end = std::chrono::steady_clock::now();

            std::cout << "Time: "
                << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "microseconds, "
                << (end - start) / std::chrono::milliseconds(1) << "ms, "
                << (end - start) / std::chrono::seconds(1) << "s.\n";

            std::cout << "Hash correct" << std::endl;
            std::cout << pass << std::endl;
            //WriteFile("plainText", plainText);
            
            break;
        }
    next:;
    }
     /*              if (pass[3] == '9')
                        pass[3] = 'a';
                }

                if (pass[2] == '9')
                    pass[2] = 'a';
            }

            if (pass[1] == '9')
                pass[1] = 'a';
        }

        if (pass[0] == '9')
            pass[0] = 'a';

        std::cout << pass[0] << std::endl;
    }*/
    
    
}

#include "Decryptor.h"
#include <mutex>

#include <thread>

std::atomic<bool> Decryptor::m_found = false;
std::atomic<int> Decryptor::m_passCount = 0;

int main()
{
    std::string pass = "pass";
    try
    {
        //Decrypt();
        std::vector<unsigned char> symbols;
        for (size_t i = 'a'; i != '9' + 1;)
        {
            symbols.push_back(i);
            if (i == 'z')
                i = '0';
            else
                ++i;
        }
        std::vector<unsigned char> chipherText;
        ReadFile("chipher_text_brute_force", chipherText);
        size_t thrNum = 1;
        std::vector<std::unique_ptr<Decryptor>> decryptors;
        for (size_t i = 0; i < thrNum; i++)
        {
            decryptors.emplace_back(std::make_unique<Decryptor>(chipherText, symbols, 4, i * symbols.size() / thrNum, (i + 1) * symbols.size() / thrNum));
        }
        /*decryptors.emplace_back(std::make_unique<Decryptor>(chipherText, symbols, 4, 0, 1 * symbols.size() / 4));
        decryptors.emplace_back(std::make_unique<Decryptor>(chipherText, symbols, 4, 1 * symbols.size() / 4, 2 * symbols.size() / 4));
        decryptors.emplace_back(std::make_unique<Decryptor>(chipherText, symbols, 4, 2 * symbols.size() / 4, 3 * symbols.size() / 4));
        decryptors.emplace_back(std::make_unique<Decryptor>(chipherText, symbols, 4, 3 * symbols.size() / 4, symbols.size()));*/

        /*Decryptor dec1(chipherText, symbols, 4, 0, 1 * symbols.size() / 4);
        Decryptor dec2(chipherText, symbols, 4, 1 * symbols.size() / 4, 2 * symbols.size() / 4);
        Decryptor dec3(chipherText, symbols, 4, 2 * symbols.size() / 4, 3 * symbols.size() / 4);
        Decryptor dec4(chipherText, symbols, 4, 3 * symbols.size() / 4, symbols.size());*/

        const std::chrono::time_point<std::chrono::steady_clock> start =
            std::chrono::steady_clock::now();


        for (auto& dec : decryptors)
        {
            std::thread([&] {dec->Decrypt(); }).detach();
        }

        /*std::thread([&] {dec1.Decrypt(); }).detach();
        std::thread([&] {dec2.Decrypt(); }).detach();
        std::thread([&] {dec3.Decrypt(); }).detach();
        std::thread([&] {dec4.Decrypt(); }).detach();*/

        unsigned int maxPassCount = pow(symbols.size(), 4);

        while (!Decryptor::m_found)
        {
            /*3333 from 10000 passwords checked[33 %]
                Time elapsed : 1m 35s
                Speed : 35 pass / sec*/
            system("cls");
            auto time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
            std::cout << Decryptor::m_passCount << " from " << maxPassCount << " passwords checked ["
                << Decryptor::m_passCount / (double)maxPassCount * 100 << " %]" << std::endl
                << "Time elapsed: " << time.count() << " microseconds" << std::endl
                << "Speed: " << Decryptor::m_passCount / (time / std::chrono::milliseconds(1)) << " pass / ms" << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        const auto end = std::chrono::steady_clock::now();
        
        for (size_t i = 0; i < 50;++i)
        {
            //std::cout << decryptors[0]->m_checkedPass[i].data() << std::endl;
        }
        /*count += dec1.passCount();
        count += dec2.passCount();
        count += dec3.passCount();
        count += dec4.passCount();*/

        //Decryptor dec(chipherText, symbols, 4, 3 * symbols.size() / 4, symbols.size());
        //dec.Decrypt();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        std::cout << "Thread num: " << thrNum << std::endl;
        std::cout << "CountPass: " << Decryptor::m_passCount << std::endl;
        std::cout << "Time: "
            << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "microseconds, "
            << (end - start) / std::chrono::milliseconds(1) << "ms, "
            << (end - start) / std::chrono::seconds(1) << "s.\n";
        system("pause");
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
    return 0;
}