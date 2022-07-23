#pragma once
#include <atomic>
#include <vector>
#include <string>

#include "openssl/evp.h"
#include "openssl/sha.h"

class Decryptor
{
public:
    Decryptor(const std::vector<unsigned char>& chipherText, const std::vector<unsigned char>& symbols, const size_t& passSize);
    bool Decrypt();
    int passCount() const;
    std::string info();

private:
    void calculateHash(unsigned char* data, size_t size);
    void nextPass();

private:
    std::string m_info;
    std::vector<unsigned char> m_symbols;
    std::vector<size_t> m_curIndex;

    std::vector<unsigned char> m_pass;
    size_t m_passSize;

    std::vector<unsigned char> m_chipherText;

    unsigned char m_key[EVP_MAX_KEY_LENGTH];
    unsigned char m_iv[EVP_MAX_IV_LENGTH];
    std::vector<unsigned char> m_hashTmp;

    std::atomic<int> m_passCount = 0;
};

