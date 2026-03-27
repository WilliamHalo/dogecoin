# BIP39 助记词导入功能实现指南

## 概述

本文档说明如何在 Dogecoin Core 中实现 BIP39 助记词导入功能，使钱包能够：
1. 导入 BIP39 助记词
2. 从助记词派生种子和 HD 主密钥
3. 生成 BIP32/BIP44 路径的地址
4. 将加密的助记词种子保存到 wallet.dat
5. 钱包加密时同时加密助记词

## 已创建的文件

### 1. src/wallet/bip39.h
定义了 BIP39 相关的类和数据结构：
- `CMnemonic`: BIP39 助记词类，提供生成、验证和种子派生功能
- `CMnemonicData`: 助记词数据模型，用于存储到钱包数据库

### 2. src/wallet/bip39.cpp
实现了 BIP39 的核心功能：
- `CMnemonic::Generate()`: 生成随机助记词
- `CMnemonic::Validate()`: 验证助记词有效性
- `CMnemonic::ToSeed()`: 从助记词派生 64 字节种子
- `CMnemonic::Split()/Join()`: 助记词字符串处理
- `CMnemonic::IsValidWord()`: 检查单词是否在 BIP39 单词表中

## 需要完成的修改

### 3. 修改 src/wallet/walletdb.h

在 `CWalletDB` 类中添加以下方法声明（已在进行中）：

```cpp
//! BIP39 mnemonic support
bool WriteMnemonic(const uint256& mnMasterKeyID, const CMnemonicData& data);
bool ReadMnemonic(uint256& mnMasterKeyID, CMnemonicData& data);
bool EraseMnemonic();
```

### 4. 修改 src/wallet/walletdb.cpp

在文件末尾添加实现（已在进行中）：

```cpp
bool CWalletDB::WriteMnemonic(const uint256& mnMasterKeyID, const CMnemonicData& data)
{
    nWalletDBUpdateCounter++;
    return Write(std::make_pair(std::string("mnemonic"), mnMasterKeyID), data);
}

bool CWalletDB::ReadMnemonic(uint256& mnMasterKeyID, CMnemonicData& data)
{
    return Read(std::make_pair(std::string("mnemonic"), mnMasterKeyID), data);
}

bool CWalletDB::EraseMnemonic()
{
    nWalletDBUpdateCounter++;
    return Erase(std::string("mnemonic"));
}
```

### 5. 修改 src/wallet/wallet.h

在 `CWallet` 类中添加成员变量和方法：

**成员变量（添加到 private 部分）：**
```cpp
//! BIP39 mnemonic data
CMnemonicData mnemonicData;
uint256 mnMasterKeyID;
```

**方法声明（添加到 public 部分）：**
```cpp
//! BIP39 mnemonic management
bool ImportMnemonic(const SecureString& strMnemonic, const SecureString& strPassphrase = "");
bool EncryptMnemonic(const CKeyingMaterial& vMasterKey);
bool DecryptMnemonic(const CKeyingMaterial& vMasterKey);
bool HasMnemonic() const { return !mnemonicData.IsNull(); }
void DeriveKeysFromMnemonic(uint32_t nCount = 20);
```

### 6. 修改 src/wallet/wallet.cpp

添加助记词导入和密钥派生实现：

```cpp
bool CWallet::ImportMnemonic(const SecureString& strMnemonic, const SecureString& strPassphrase)
{
    // 1. 验证助记词
    if (!CMnemonic::Validate(strMnemonic))
        return error("Invalid mnemonic");

    // 2. 派生种子
    std::vector<unsigned char> seed;
    if (!CMnemonic::ToSeed(strMnemonic, strPassphrase, seed))
        return error("Failed to derive seed");

    // 3. 设置 HD 主密钥
    CExtKey masterKey;
    masterKey.SetMaster(seed.data(), seed.size());
    
    mnMasterKeyID = masterKey.key.GetPubKey().GetID();
    
    // 4. 设置 HD 链
    hdChain.nExternalChainCounter = 0;
    hdChain.masterKeyID = mnMasterKeyID;
    
    // 5. 存储助记词（如果钱包已加密，则存储加密版本）
    mnemonicData.mnMasterKeyID = mnMasterKeyID;
    mnemonicData.nCreateTime = GetTime();
    mnemonicData.fEncrypted = IsCrypted();
    
    if (IsCrypted()) {
        // 加密助记词
        SecureString strMnemonicCopy = strMnemonic;
        std::vector<unsigned char> vchMnemonic(strMnemonicCopy.begin(), strMnemonicCopy.end());
        std::vector<unsigned char> vchCryptedMnemonic;
        
        uint256 iv = Hash(mnMasterKeyID.begin(), mnMasterKeyID.end());
        if (!EncryptSecret(vMasterKey, vchMnemonic, iv, vchCryptedMnemonic))
            return error("Failed to encrypt mnemonic");
        
        mnemonicData.vchCryptedMnemonic = vchCryptedMnemonic;
    } else {
        // 未加密钱包，暂时不存储明文助记词
        // 用户应该已经备份了助记词
        mnemonicData.vchCryptedMnemonic.clear();
    }
    
    // 6. 写入数据库
    CWalletDB walletdb(strWalletFile);
    if (!walletdb.WriteMnemonic(mnMasterKeyID, mnemonicData))
        return error("Failed to write mnemonic to database");
    
    if (!walletdb.WriteHDChain(hdChain))
        return error("Failed to write HD chain");
    
    // 7. 派生初始密钥
    DeriveKeysFromMnemonic(20);
    
    return true;
}

bool CWallet::EncryptMnemonic(const CKeyingMaterial& vMasterKeyIn)
{
    if (!HasMnemonic())
        return true;
    
    // 助记词将在 SetCrypted 时通过 EncryptKeys 流程处理
    // 这里只需要标记需要加密
    return true;
}

bool CWallet::DecryptMnemonic(const CKeyingMaterial& vMasterKeyIn)
{
    if (!HasMnemonic() || !mnemonicData.fEncrypted)
        return true;
    
    // 解密助记词
    SecureString strMnemonic;
    std::vector<unsigned char> vchDecrypted;
    uint256 iv = Hash(mnMasterKeyID.begin(), mnMasterKeyID.end());
    
    if (!DecryptSecret(vMasterKeyIn, mnemonicData.vchCryptedMnemonic, iv, vchDecrypted))
        return error("Failed to decrypt mnemonic");
    
    strMnemonic.assign(vchDecrypted.begin(), vchDecrypted.end());
    
    // 验证解密后的助记词
    if (!CMnemonic::Validate(strMnemonic))
        return error("Decrypted mnemonic is invalid");
    
    return true;
}

void CWallet::DeriveKeysFromMnemonic(uint32_t nCount)
{
    if (mnMasterKeyID.IsNull())
        return;
    
    // 使用 BIP44 路径：m/44'/3'/0'/0/n (Dogecoin coin type = 3)
    // 或者使用更简单的路径：m/0/n
    
    CExtKey extKey;
    if (!GetKey(mnMasterKeyID, extKey.key)) {
        // 需要从种子重新生成主密钥
        // 这里应该从存储的种子或助记词派生
        return;
    }
    
    // 派生外部链密钥
    CExtKey externalChain;
    extKey.Derive(externalChain, 0);  // m/0
    
    for (uint32_t i = 0; i < nCount; i++) {
        CExtKey childKey;
        externalChain.Derive(childKey, i);  // m/0/i
        
        CPubKey pubkey = childKey.key.GetPubKey();
        CKeyID keyID = pubkey.GetID();
        
        // 添加密钥到钱包
        if (!HaveKey(keyID)) {
            CKeyMetadata keyMeta;
            keyMeta.nCreateTime = GetTime();
            keyMeta.hdKeypath = "m/0/" + std::to_string(i);
            keyMeta.hdMasterKeyID = mnMasterKeyID;
            
            AddKeyPubKey(childKey.key, pubkey);
            
            // 写入数据库
            CWalletDB walletdb(strWalletFile);
            walletdb.WriteKey(pubkey, childKey.key.GetPrivKey(), keyMeta);
        }
    }
    
    hdChain.nExternalChainCounter = nCount;
}
```

### 7. 修改 src/wallet/rpcdump.cpp

添加 RPC 接口：

```cpp
UniValue importmnemonic(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw runtime_error(
            "importmnemonic \"mnemonic\" ( \"passphrase\" rescan )\n"
            "\nImport a BIP39 mnemonic phrase to generate HD keys.\n"
            "\nArguments:\n"
            "1. \"mnemonic\"      (string, required) The mnemonic phrase (12, 15, 18, 21, or 24 words)\n"
            "2. \"passphrase\"    (string, optional) BIP39 passphrase for additional security\n"
            "3. rescan            (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nExamples:\n"
            + HelpExampleCli("importmnemonic", "\"abandon abandon ... abandon art\"") +
            HelpExampleCli("importmnemonic", "\"abandon abandon ... abandon art\" \"my passphrase\"") +
            HelpExampleRpc("importmnemonic", "\"abandon abandon ... abandon art\", \"my passphrase\"")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    SecureString strMnemonic = request.params[0].get_str().c_str();
    SecureString strPassphrase = request.params.size() > 1 ? request.params[1].get_str().c_str() : "";
    bool fRescan = request.params.size() > 2 ? request.params[2].get_bool() : true;

    // 验证助记词
    if (!CMnemonic::Validate(strMnemonic))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mnemonic phrase");

    // 导入助记词
    if (!pwallet->ImportMnemonic(strMnemonic, strPassphrase))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to import mnemonic");

    if (fRescan) {
        pwallet->ScanForWalletTransactions(chainActive.Genesis(), true);
    }

    return NullUniValue;
}

UniValue dumpmnemonic(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(request.fHelp))
        return NullUniValue;

    if (request.fHelp || request.params.size() != 0)
        throw runtime_error(
            "dumpmnemonic\n"
            "\nDumps the wallet's BIP39 mnemonic phrase.\n"
            "\nWARNING: Anyone with access to this phrase can control your funds!\n"
            "\nResult:\n"
            "\"mnemonic\"  (string) The mnemonic phrase, or empty if not available\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpmnemonic", "") +
            HelpExampleRpc("dumpmnemonic", "")
        );

    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    // 检查是否有助记词
    if (!pwallet->HasMnemonic())
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet does not have a mnemonic");

    // 解密助记词
    if (!pwallet->DecryptMnemonic(pwallet->vMasterKey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to decrypt mnemonic");

    // TODO: 返回解密后的助记词
    // 需要实现从加密数据恢复助记词的逻辑
    
    return "mnemonic decryption not fully implemented";
}
```

在 `CommandRPCActions` 表中注册新的 RPC 命令：

```cpp
static const CRPCCommand commands[] =
{
    // ... existing commands ...
    { "wallet", "importmnemonic", &importmnemonic, {"mnemonic", "passphrase", "rescan"} },
    { "wallet", "dumpmnemonic", &dumpmnemonic, {} },
};
```

### 8. 修改 src/Makefile.am

添加新文件到编译系统：

```makefile
libbitcoinconsensus_la_SOURCES += \
    wallet/bip39.cpp \
    wallet/bip39.h

libdogecoin_wallet_a_SOURCES += \
    wallet/bip39.cpp
```

## 安全考虑

1. **助记词加密存储**: 助记词应该始终加密存储，使用与钱包私钥相同的加密机制
2. **内存清理**: 使用 `SecureString` 和 `memory_cleanse()` 防止敏感数据残留
3. **访问控制**: `dumpmnemonic` 应该要求钱包解锁
4. **备份提示**: 导入助记词时应提示用户备份

## 测试建议

1. 测试助记词生成和验证
2. 测试助记词导入和密钥派生
3. 测试加密/解密助记词
4. 测试钱包恢复流程
5. 测试与现有 HD 钱包的兼容性

## 注意事项

1. 此实现需要与现有的 HD 钱包功能（BIP32）集成
2. 考虑支持 BIP44 路径（m/44'/3'/0'/0/n）
3. 确保向后兼容性，不影响现有钱包
4. 需要适当的错误处理和日志记录

## 下一步

1. 完成上述代码修改
2. 编译并测试功能
3. 添加单元测试
4. 更新文档
5. 代码审查和安全审计
