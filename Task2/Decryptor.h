#pragma once
#include <atomic>
#include <vector>
#include <string>
#include <thread>

#include "openssl/evp.h"
#include "openssl/sha.h"

class Decryptor
{
public:
    Decryptor(const std::vector<unsigned char>& chipherText, const std::vector<unsigned char>& symbols, const size_t& passSize,
        const size_t& startSymIndex, const size_t& endSymIndex);
    bool Decrypt();
    int passCount() const;
    std::string info();

    std::vector<std::vector<unsigned char>> m_checkedPass;
    static std::atomic<int> m_passCount;  
    static std::atomic<bool> m_found;

private:
    void calculateHash(unsigned char* data, size_t size);
    bool nextPass();

private:
    std::string m_info;
    size_t m_endSymIndex;
    std::vector<unsigned char> m_symbols;
    std::vector<size_t> m_curIndex;

    std::vector<unsigned char> m_pass;
    size_t m_passSize;

    std::vector<unsigned char> m_chipherText;

    unsigned char m_key[EVP_MAX_KEY_LENGTH];
    unsigned char m_iv[EVP_MAX_IV_LENGTH];
    std::vector<unsigned char> m_hashTmp;
};

