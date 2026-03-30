# BIP39 助记词导入功能实现计划

## 上下文

用户希望为 Dogecoin Core 添加 BIP39 助记词导入功能，需要：
1. 支持通过 BIP39 助记词导入种子
2. 所有地址按照 BIP44 方式生成（当前已经是 BIP44 路径 `m/0'/3'/k'`）
3. 将助记词种子保存在 wallet.dat 中
4. 钱包加密时自动加密助记词种子

## 当前状态分析

Dogecoin Core 已支持 BIP32 HD 钱包：
- 主密钥生成：`CWallet::GenerateNewHDMasterKey()` 在 `src/wallet/wallet.cpp`
- 密钥派生：`CWallet::DeriveNewChildKey()` 使用路径 `m/0'/3'/k'`
- 数据库存储：`CHDChain` 类存储 HD 链信息，`CKeyMetadata` 存储密钥元数据
- 加密机制：`CCrypter` 类使用 AES-256-CBC，`CMasterKey` 管理主加密密钥

## 实现方案

### 方案：添加 BIP39 种子导入功能

在现有 BIP32 基础上添加 BIP39 助记词支持，修改现有架构而非替换。

**优势：**
- 向后兼容：现有随机生成的主密钥仍然有效
- 用户选择：可选择通过助记词导入或传统方式创建钱包
- 复用现有代码：BIP32 派生逻辑无需修改

**劣势：**
- 需要修改数据库结构存储助记词
- 加密逻辑需要扩展以覆盖助记词

## 详细实现步骤

### 1. 创建 BIP39 核心类 (`src/bip39.h`, `src/bip39.cpp`)

**功能：**
- 2048 词英语助记词表
- 助记词生成熵：`GenerateMnemonic(entropy, wordList)`
- 助记词验证：`ValidateMnemonic(words, wordList)`
- 种子派生：`MnemonicToSeed(words, passphrase)` 使用 PBKDF2-HMAC-SHA512，迭代 2048 次

**关键代码（预估）：**
```cpp
// MnemonicToSeed 实现
std::vector<unsigned char> MnemonicToSeed(const std::string& mnemonic, const std::string& passphrase) {
    const std::string salt = "mnemonic" + passphrase;
    std::vector<unsigned char> seed(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.length(),
                      (const unsigned char*)salt.c_str(), salt.length(),
                      2048, EVP_sha512(), 64, seed.data());
    return seed;
}
```

### 2. 扩展 CHDChain 类 (`src/wallet/walletdb.h`)

**修改内容：**
```cpp
class CHDChain {
public:
    uint32_t nExternalChainCounter;
    CKeyID masterKeyID;
    bool fFromMnemonic;        // 新增：是否从助记词生成
    std::vector<unsigned char> vchMnemonicSeed; // 新增：加密的助记词种子
    // ... 序列化更新
};
```

### 3. 扩展钱包加密类 (`src/wallet/crypter.h`, `src/wallet/crypter.cpp`)

**新增：**
- `EncryptMnemonic()` 方法
- `DecryptMnemonic()` 方法
- 扩展 `vMasterKey` 加密范围以覆盖助记词数据

### 4. 修改 CWallet 类 (`src/wallet/wallet.h`, `src/wallet/wallet.cpp`)

**新增方法：**
```cpp
// 从助记词生成钱包
bool GenerateFromMnemonic(const std::string& mnemonic, const std::string& passphrase = "");

// 获取当前助记词（需要解锁）
std::string GetMnemonic() const;

// 设置助记词种子并派生主密钥
bool SetHDMasterKeyFromSeed(const std::vector<unsigned char>& seed);
```

**修改现有方法：**
- `EncryptWallet()`：加密时同时加密 vchMnemonicSeed
- `Unlock()`：解锁时解密 vchMnemonicSeed 到内存

### 5. 扩展钱包数据库 (`src/wallet/walletdb.h`, `src/wallet/walletdb.cpp`)

**新增存储键：**
- `"mnemonicseed"` -> 存储加密的助记词种子
- `"hdchain"` 序列化更新以包含 fFromMnemonic 标志

**修改方法：**
- `WriteHDChain()`：写入更新后的 CHDChain
- `ReadHDChain()`：读取并迁移旧格式

### 6. 添加 RPC 命令 (`src/wallet/rpcwallet.cpp`)

**新增命令：**
```cpp
// 从助记词恢复钱包
{"importmnemonic", &importmnemonic, ...}

// 导出现有助记词
{"dumpmnemonic", &dumpmnemonic, ...}

// 生成新助记词钱包
{"generatemnemonic", &generatemnemonic, ...}
```

### 7. Qt GUI 集成 (`src/qt/`)

**新增界面：**
- 启动向导：选择"创建新钱包"或"从助记词恢复"
- 助记词输入对话框（支持输入或显示）
- 钱包加密时确认助记词已安全存储

## 数据流图

```
1. 助记词导入流程:
   用户输入助记词 -> MnemonicToSeed() -> seed[64 bytes]
                                    |
                                    v
   CWallet::GenerateFromMnemonic() -> seed -> SetHDMasterKeyFromSeed()
                                    |
                                    v
                            CExtKey::SetMaster(seed, 64)
                                    |
                                    v
                            派生主密钥 -> AddKeyPubKey()
                                    |
                                    v
                            设置 hdChain.fFromMnemonic = true
                            保存助记词种子到 vchMnemonicSeed
                                    |
                                    v
                            CWalletDB::WriteHDChain()

2. 钱包加密流程:
   EncryptWallet(passphrase) -> 派生 vMasterKey <- 用户密码
                                    |
                                    v
                            for each key: EncryptSecret()
                            EncryptMnemonic(vchMnemonicSeed)
                                    |
                                    v
                            CWalletDB::WriteCryptedMnemonic()
```

## 关键文件修改列表

| 文件 | 修改类型 | 说明 |
|------|----------|------|
| `src/bip39.h` | 新增 | BIP39 助记词接口 |
| `src/bip39.cpp` | 新增 | BIP39 实现（词表+PBKDF2） |
| `src/wallet/walletdb.h` | 修改 | 扩展 CHDChain 类 |
| `src/wallet/walletdb.cpp` | 修改 | 读写助记词数据 |
| `src/wallet/wallet.h` | 修改 | 添加 BIP39 相关方法 |
| `src/wallet/wallet.cpp` | 修改 | 实现助记词导入逻辑 |
| `src/wallet/crypter.h` | 修改 | 添加助记词加密接口 |
| `src/wallet/crypter.cpp` | 修改 | 实现助记词加密 |
| `src/wallet/rpcwallet.cpp` | 修改 | 添加 RPC 命令 |
| `src/qt/` | 修改 | UI 集成 |
| `src/Makefile.am` | 修改 | 添加新源文件到构建 |

## 安全性考虑

1. **助记词存储**：使用 AES-256-CBC 加密，密钥为主钱包加密密钥 vMasterKey
2. **内存安全**：使用 secure_allocator，助记词字符串在内存中立即擦除
3. **密码派生**：PBKDF2 2048 次迭代（BIP39 标准）
4. **兼容性**：未加密钱包允许访问助记词，但 UI 会警告风险

## 测试方案

1. **单元测试**：
```cpp
BOOST_AUTO_TEST_CASE(bip39_mnemonic_to_seed) {
    std::string mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    std::vector<unsigned char> seed = MnemonicToSeed(mnemonic, "");
    // 验证预期种子值
}
```

2. **集成测试**：
   - 创建助记词钱包 -> 生成地址 -> 验证地址
   - 加密钱包 -> 解锁 -> 导出助记词
   - 助记词恢复 -> 验证相同地址

3. **兼容性测试**：
   - 加载旧 wallet.dat（无 BIP39 数据）
   - 混合使用随机密钥和助记词密钥

## 参考实现

参考 Bitcoin ABC 和 Bitcoin Core 的 BIP39 实现：
- `src/bip39.h` 和 `src/bip39.cpp` 模式类似
- 使用 OpenSSL `PKCS5_PBKDF2_HMAC` 进行 PBKDF2

## 依赖项

需要 OpenSSL 库（已有依赖）用于：
- `PKCS5_PBKDF2_HMAC` - PBKDF2 密钥派生
- `EVP_sha512()` - SHA-512 哈希
- AES-256-CBC 加密（已有）
