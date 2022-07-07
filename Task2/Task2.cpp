#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

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

void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
    std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
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
    if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
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

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
    std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, &data[0], data.size());
    SHA256_Final(&hashTmp[0], &sha256);

    hash.swap(hashTmp);
}

void Encrypt()
{
    std::vector<unsigned char> plainText;
    ReadFile("plain_text", plainText);

    std::vector<unsigned char> hash;
    CalculateHash(plainText, hash);

    std::vector<unsigned char> chipherText;
    EncryptAes(plainText, chipherText);

    WriteFile("chipher_text", chipherText);

    AppendToFile("chipher_text", hash);
}

void Decrypt()
{
    std::vector<unsigned char> chipherText;
    ReadFile("chipher_text_brute_force", chipherText);

    std::vector<unsigned char> hash;

    std::vector<unsigned char> hashText(chipherText.begin() + chipherText.size() - SHA256_DIGEST_LENGTH, chipherText.end());
    chipherText.erase(chipherText.begin() + chipherText.size() - SHA256_DIGEST_LENGTH, chipherText.end());

    std::vector<unsigned char> plainText;

    std::vector<unsigned char> bu = { 'a','b','c' };

    for (unsigned char a = 'k'; a <= 'z'; ++a)
    {
        for (unsigned char b = '0'; b <= 'z'; ++b)
        {
            for (unsigned char c = '0'; c <= 'z'; ++c)
            {
                for (unsigned char d = '0'; d <= 'z'; ++d)
                {
                    PasswordToKey({ a,b,c,d });
                    if (DecryptAes(chipherText, plainText))
                    {
                        CalculateHash(plainText, hash);

                        if (hash == hashText)
                        {
                            std::cout << "Hash correct" << std::endl;
                            std::cout << a << b << c << d << std::endl;
                            WriteFile("plainText", plainText);
                            system("pause");
                            break;
                        }
                    }
                    if (d == '9')
                        d = 'a';
                }

                if (c == '9')
                    c = 'a';
            }

            if (b == '9')
                b = 'a';
        }

        if (a == '9')
            a = 'a';

        std::cout << a << std::endl;
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