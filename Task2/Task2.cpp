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

void CalculateHash(unsigned char* data, size_t size, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
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
    pass[passSize] = '\0';

    for (pass[0] = '0'; pass[0] <= 'z'; ++pass[0])
    {
        for (pass[1] = '0'; pass[1] <= 'z'; ++pass[1])
        {
            for (pass[2] = '0'; pass[2] <= 'z'; ++pass[2])
            {
                for (pass[3] = '0'; pass[3] <= 'z'; ++pass[3])
                {

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

                        

                        CalculateHash(&chipherTextBuf[0], chipherTextSize, hash);

                        if (hash == hashText)
                        {
                            const auto end = std::chrono::steady_clock::now();

                            std::cout << "Time: "
                                << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "micro sec = "
                                << (end - start) / std::chrono::microseconds(1) << "ms = " // almost equivalent form of the above, but
                                << (end - start) / std::chrono::seconds(1) << "s.\n";  // using milliseconds and seconds accordingly

                            std::cout << "Hash correct" << std::endl;
                            std::cout << pass << std::endl;
                            //WriteFile("plainText", plainText);
                            system("pause");
                            break;
                        }
                    next:;
                    if (pass[3] == '9')
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
    }
    
    
}

int main()
{
    std::string pass = "pass";
    try
    {
        //PasswordToKey(pass);
        Decrypt();
    }
    catch (const std::runtime_error& ex)
    {
        std::cerr << ex.what();
    }
}