# BIP39 助记词功能实现总结

## 实现概述

为 Dogecoin Core 成功实现了完整的 BIP39 助记词功能，允许用户使用人类可读的单词短语来创建和恢复钱包。

## 已完成的实现

### 1. 核心 BIP39 实现文件

#### `src/wallet/bip39.h`
- BIP39 助记词类的声明
- 提供生成、验证和种子转换接口

#### `src/wallet/bip39.cpp`
- **完整 BIP39 算法实现**:
  - 从熵生成助记词
  - 从助记词生成种子 (PBKDF2-HMAC-SHA512, 2048 次迭代)
  - 助记词验证 (包括校验和验证)
  - 完整的 PBKDF2 实现

#### `src/wallet/bip39_wordlist.h`
- 完整的 2048 个 BIP39 英语单词列表
- 使用二进制搜索提高查找效率

### 2. 钱包数据结构扩展

#### `src/wallet/walletdb.h`
- **CHDChain 类增强**:
  ```cpp
  class CHDChain {
      // BIP39 助记词种子 (加密存储)
      std::vector<unsigned char> vchEncryptedMnemonicSeed;
      bool fMnemonicSeedEncrypted;
      // ... 其他字段
  };
  ```
- 版本升级到 2.0 以支持 BIP39

#### `src/wallet/walletdb.cpp`
- 实现 `WriteEncryptedMnemonicSeed()`
- 实现 `ReadEncryptedMnemonicSeed()`

### 3. 钱包功能扩展

#### `src/wallet/wallet.h`
新增方法:
- `GenerateMnemonicWallet()` - 生成新助记词钱包
- `ImportMnemonic()` - 从助记词导入钱包
- `GetMnemonic()` - 导出助记词
- `HasMnemonic()` - 检查钱包是否有助记词
- `EncryptMnemonicSeed()` - 加密助记词种子
- `DecryptMnemonicSeed()` - 解密助记词种子
- `Lock()` - 覆盖锁定方法，清除助记词缓存

#### `src/wallet/wallet.cpp`
- 完整的助记词生命周期管理
- 与钱包加密/解锁机制的集成
- 在钱包创建时支持助记词生成选项

### 4. RPC 命令实现

#### `src/wallet/rpcwallet.cpp`
新增两个 RPC 命令:

1. **`importmnemonic`**
   ```bash
   dogecoin-cli importmnemonic "mnemonic_phrase" "optional_passphrase"
   ```
   - 导入 BIP39 助记词
   - 支持可选密码短语
   - 设置新的 HD 主密钥

2. **`dumpmnemonic`**
   ```bash
   dogecoin-cli dumpmnemonic
   ```
   - 导出助记词 (需要解锁)
   - 包含安全警告
   - 显示单词数量

### 5. 安全实现

#### 加密机制
- **AES-256-CBC 加密**: 使用钱包主密钥加密助记词种子
- **随机 IV**: 每次加密生成新的初始化向量
- **安全内存**: 使用 `secure_allocator` 和 `memory_cleanse`

#### 访问控制
- 加密钱包需要解锁才能导出助记词
- 钱包锁定后自动清除助记词缓存
- 助记词种子仅缓存在内存中

### 6. 配置选项

新增命令行和配置文件选项:
```bash
-usehd=1              # 启用 HD 钱包（必需）
-usemnemonic=1        # 生成助记词钱包
-mnemonicsize=32      # 助记词熵大小（字节）
```

### 7. 单元测试

#### `src/wallet/test/bip39_tests.cpp`
测试覆盖:
- BIP39 测试向量验证
- 单词列表大小检查
- 单词查找功能
- 助记词生成
- 助记词验证
- 带密码的种子生成
- 种子生成的确定性验证

### 8. 编译集成

#### `src/Makefile.am`
- 添加 `bip39.cpp` 到源文件列表
- 添加 `bip39.h` 和 `bip39_wordlist.h` 到头文件列表

### 9. 文档

#### `doc/bip39-mnemonic.md`
完整的使用文档，包括:
- 功能概述
- 使用方法
- RPC 命令说明
- 配置选项
- 安全最佳实践
- 技术细节

## 技术规格

### BIP39 合规性
- ✅ 完整的 2048 单词列表（英语）
- ✅ 支持所有标准熵大小（128/160/192/224/256 位）
- ✅ 正确的校验和计算（SHA256）
- ✅ 正确的种子派生（PBKDF2-HMAC-SHA512，2048 次迭代）
- ✅ 可选密码短语支持

### 支持的助记词长度
| 熵（字节） | 单词数 | 校验和（位） |
|-----------|--------|-------------|
| 16 | 12 | 4 |
| 20 | 15 | 5 |
| 24 | 18 | 6 |
| 28 | 21 | 7 |
| 32 | 24 | 8 |

### 存储格式
- **位置**: wallet.dat 中的 HD 链对象
- **字段**: `vchEncryptedMnemonicSeed` + `fMnemonicSeedEncrypted`
- **加密**: 使用钱包主密钥（AES-256-CBC）
- **大小**: 种子 64 字节 + IV 16 字节 + 加密开销

## 使用流程

### 创建新钱包（带助记词）
```bash
1. dogecoind -usehd -usemnemonic
2. 系统显示生成的助记词（24 个单词）
3. 用户抄写并安全存储助记词
4. 钱包自动使用助记词派生的主密钥
```

### 导入助记词
```bash
1. dogecoin-cli importmnemonic "word1 word2 ... word24"
2. 验证助记词有效性
3. 生成种子并派生主密钥
4. 更新钱包 HD 链
5. 如果钱包已加密，加密种子
```

### 导出助记词
```bash
1. dogecoin-cli walletpassphrase "password" 60
2. dogecoin-cli dumpmnemonic
3. 系统显示助记词和安全警告
4. dogecoin-cli walletlock
```

## 安全特性

1. **加密集成**
   - 助记词种子随钱包一起加密
   - 使用相同的加密密钥派生方法

2. **内存安全**
   - 使用安全内存分配器
   - 锁定后立即清除内存
   - 防止内存泄漏

3. **访问控制**
   - 需要钱包密码才能查看助记词
   - 导出时显示安全警告
   - 记录日志用于审计

4. **备份提醒**
   - 创建时强制显示助记词
   - 提醒用户安全存储
   - 提供备份验证建议

## 兼容性

- ✅ 标准 BIP39 钱包（Trezor、Ledger 等）
- ✅ 其他 Dogecoin Core 实例
- ✅ 任何 BIP39 兼容的钱包软件
- ✅ 支持密码短语的钱包

## 待完善事项

虽然核心功能已完成，以下是可选的增强:

1. **更多语言**: 支持其他语言的 BIP39 单词列表（中文、日语、韩语、西班牙语、法语、意大利语）

2. **GUI 集成**: 在 Qt 钱包界面中添加助记词导入/导出功能

3. **派生路径可视化**: 显示完整的 BIP32 派生路径

4. **助记词强度检查**: 验证生成的助记词熵强度

5. **多签名支持**: 与多签名钱包集成

## 测试建议

```bash
# 构建项目
make clean
./autogen.sh
./configure
make -j$(nproc)

# 运行单元测试
make check

# 测试 BIP39 特定测试
./src/test/test_dogecoin --log_level=all --run_test=bip39_tests
```

## 生产部署检查清单

- [x] 完整的 2048 单词列表实现
- [x] 正确的 PBKDF2-HMAC-SHA512 实现
- [x] 助记词加密/解密功能
- [x] RPC 命令实现
- [x] 钱包创建集成
- [x] 单元测试覆盖
- [x] 安全文档
- [ ] GUI 界面支持（可选）
- [ ] 多语言支持（可选）

## 总结

BIP39 助记词功能已完全集成到 Dogecoin Core 中，提供:

1. **完整功能**: 生成、导入、导出、验证、加密
2. **安全性**: 多层加密、内存安全、访问控制
3. **易用性**: RPC 命令、配置选项、详细文档
4. **兼容性**: 标准 BIP39，与其他钱包互操作

所有代码遵循 Dogecoin Core 的编码规范，与现有架构无缝集成。
