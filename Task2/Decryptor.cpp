#include "Decryptor.h"

#include <chrono>
#include <iostream>

#include <openssl/aes.h>
#include <openssl/md5.h>

Decryptor::Decryptor(const std::vector<unsigned char>& chipherText, const std::vector<unsigned char>& symbols, const size_t& passSize,
    const size_t& startSymIndex, const size_t& endSymIndex)
    : m_chipherText(chipherText), m_symbols(symbols), m_passSize(passSize), m_endSymIndex(endSymIndex)
{
    m_hashTmp.resize(SHA256_DIGEST_LENGTH);
    m_pass.resize(m_passSize + 1);
    for (size_t i = 0; i < m_passSize - 1; i++)
        m_pass[i] = m_symbols[0];

    m_pass[passSize - 1] = m_symbols[startSymIndex];
    m_pass[passSize] = '\0';

    m_curIndex.resize(m_passSize, 0);
    m_curIndex[m_passSize - 1] = startSymIndex;
}

bool Decryptor::Decrypt()
{
    std::vector<unsigned char> textHash(m_chipherText.begin() + m_chipherText.size() - SHA256_DIGEST_LENGTH, m_chipherText.end());
    m_chipherText.erase(m_chipherText.begin() + m_chipherText.size() - SHA256_DIGEST_LENGTH, m_chipherText.end());

    std::vector<unsigned char> chipherTextBuf(m_chipherText.size() + AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    const std::chrono::time_point<std::chrono::steady_clock> start =
        std::chrono::steady_clock::now();

    while (nextPass() && !m_found)
    {       
        std::this_thread::sleep_for(std::chrono::nanoseconds(5));
        if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), nullptr, &m_pass[0], m_passSize, 1, m_key, m_iv))
        {
            m_info = "EVP_BytesToKey failed";
            return 0;
        }

        if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, m_key, m_iv))
        {
            m_info = "EncryptInit error";
            return 0;
        }


        int chipherTextSize = 0;
        if (!EVP_DecryptUpdate(ctx, &chipherTextBuf[0], &chipherTextSize, &m_chipherText[0], m_chipherText.size())) {
            EVP_CIPHER_CTX_free(ctx);
            m_info = "Encrypt error";
            return 0;
        }

        int lastPartLen = 0;
        if (!EVP_DecryptFinal_ex(ctx, &chipherTextBuf[0] + chipherTextSize, &lastPartLen)) {
            EVP_CIPHER_CTX_cleanup(ctx);
            goto next;
        }
        chipherTextSize += lastPartLen;

        EVP_CIPHER_CTX_cleanup(ctx);

        calculateHash(&chipherTextBuf[0], chipherTextSize);
        if (m_hashTmp == textHash)
        {
            m_found = true;
            //m_info = std::string(m_pass.data());
           /* const auto end = std::chrono::steady_clock::now();

            std::cout << "Time: "
                << std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() << "microseconds, "
                << (end - start) / std::chrono::milliseconds(1) << "ms, "
                << (end - start) / std::chrono::seconds(1) << "s.\n";

            std::cout << "Hash correct" << std::endl;
            std::cout << m_pass.data() << std::endl;*/
            EVP_CIPHER_CTX_free(ctx);
            return 1;
        }
    next:;
    }
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

int Decryptor::passCount() const
{
    return m_passCount;
}

std::string Decryptor::info()
{
    return m_info;
}

void Decryptor::calculateHash(unsigned char* data, size_t size)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(&m_hashTmp[0], &sha256);
}

bool Decryptor::nextPass()
{
    m_pass[0] = m_symbols[m_curIndex[0]++];
    for (size_t i = 0; i < m_passSize; i++)
    {
        if (m_curIndex[i] == m_symbols.size())
        {
            m_curIndex[i] = 0;
            if (i + 1 < m_passSize)
            {
                m_pass[i + 1] = m_symbols[m_curIndex[i + 1]++];
                break;
            }
        }
    }
    if (m_curIndex[m_passSize - 1] == m_endSymIndex)
        return false;
    m_checkedPass.push_back(m_pass);
    m_passCount++;
    return true;
}
