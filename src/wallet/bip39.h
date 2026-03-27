// Copyright (c) 2024 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_BIP39_H
#define BITCOIN_WALLET_BIP39_H

#include "key.h"
#include "uint256.h"
#include "support/allocators/secure.h"
#include "support/cleanse.h"

#include <string>
#include <vector>
#include <map>

/** BIP39 单词列表大小 */
static const int BIP39_WORDLIST_SIZE = 2048;

/** 支持的助记词长度（单词数） */
static const int BIP39_MNEMONIC_LENGTH_12 = 12;
static const int BIP39_MNEMONIC_LENGTH_15 = 15;
static const int BIP39_MNEMONIC_LENGTH_18 = 18;
static const int BIP39_MNEMONIC_LENGTH_21 = 21;
static const int BIP39_MNEMONIC_LENGTH_24 = 24;

/** 熵的长度（字节） */
static const int BIP39_ENTROPY_LEN_128 = 16;
static const int BIP39_ENTROPY_LEN_160 = 20;
static const int BIP39_ENTROPY_LEN_192 = 24;
static const int BIP39_ENTROPY_LEN_224 = 28;
static const int BIP39_ENTROPY_LEN_256 = 32;

/** BIP39 种子长度（字节） */
static const int BIP39_SEED_LEN = 64;

/** BIP39 单词列表（英语） */
extern const char* const BIP39_WORDLIST[];

/**
 * BIP39 助记词类
 * 提供助记词的生成、验证和种子派生功能
 */
class CMnemonic
{
public:
    /**
     * 生成随机助记词
     * @param nEntropyLen 熵的长度（16, 20, 24, 28, 32 字节）
     * @param strMnemonic 输出的助记词字符串（空格分隔的单词）
     * @return true 如果生成成功
     */
    static bool Generate(int nEntropyLen, SecureString& strMnemonic);

    /**
     * 验证助记词是否有效
     * @param strMnemonic 助记词字符串
     * @return true 如果助记词有效
     */
    static bool Validate(const SecureString& strMnemonic);

    /**
     * 从助记词派生种子
     * @param strMnemonic 助记词字符串
     * @param strPassphrase 可选的密码短语
     * @param seedOut 输出的 64 字节种子
     * @return true 如果派生成功
     */
    static bool ToSeed(const SecureString& strMnemonic, const SecureString& strPassphrase, std::vector<unsigned char>& seedOut);

    /**
     * 将助记词拆分为单词列表
     * @param strMnemonic 助记词字符串
     * @param words 输出的单词向量
     * @return true 如果拆分成功
     */
    static bool Split(const SecureString& strMnemonic, std::vector<std::string>& words);

    /**
     * 将单词列表组合为助记词字符串
     * @param words 单词向量
     * @return 助记词字符串
     */
    static SecureString Join(const std::vector<std::string>& words);

    /**
     * 检查单词是否在 BIP39 单词列表中
     * @param word 要检查的单词
     * @return true 如果单词在列表中
     */
    static bool IsValidWord(const std::string& word);

    /**
     * 获取熵的校验和位数
     * @param nEntropyLen 熵的长度
     * @return 校验和位数
     */
    static int GetChecksumBits(int nEntropyLen);

private:
    /**
     * 计算熵的校验和
     * @param entropy 熵数据
     * @param nEntropyLen 熵的长度
     * @return 校验和字节
     */
    static unsigned char CalculateChecksum(const unsigned char* entropy, int nEntropyLen);

    /**
     * 查找单词在单词列表中的索引
     * @param word 单词
     * @return 索引（0-2047），如果未找到返回 -1
     */
    static int WordIndex(const std::string& word);
};

/**
 * 助记词数据模型，用于存储到钱包数据库
 */
class CMnemonicData
{
public:
    static const int CURRENT_VERSION = 1;
    int nVersion;
    
    /** 加密后的助记词 */
    std::vector<unsigned char> vchCryptedMnemonic;
    
    /** 助记词 Master Key ID（用于标识） */
    CKeyID mnMasterKeyID;
    
    /** 创建时间戳 */
    int64_t nCreateTime;
    
    /** 是否已加密 */
    bool fEncrypted;

    CMnemonicData()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(this->nVersion);
        READWRITE(vchCryptedMnemonic);
        READWRITE(mnMasterKeyID);
        READWRITE(nCreateTime);
        READWRITE(fEncrypted);
    }

    void SetNull()
    {
        nVersion = CMnemonicData::CURRENT_VERSION;
        vchCryptedMnemonic.clear();
        mnMasterKeyID.SetNull();
        nCreateTime = 0;
        fEncrypted = false;
    }

    bool IsNull() const
    {
        return vchCryptedMnemonic.empty() && mnMasterKeyID.IsNull();
    }
};

#endif // BITCOIN_WALLET_BIP39_H
