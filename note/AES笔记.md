# AES 笔记

AES 全称 Advanced Encryption Standard ，翻译为高级加密标准，是一种对称加密算法。

| 标准     | 主钥二进制位数 | 加密轮数 |
|--------|---------|------|
| AES128 | 128     | 10   |
| AES192 | 192     | 12   |
| AES256 | 256     | 14   |

初始化时，要提供对应长度的主钥，以此来生成用于后续计算的数据，轮数越多，要储存的数据也越多，后续的计算复杂度也更大。

它的加密和解密就是对一个 4 * 4 的字节矩阵进行各种操作，包括字节替换，各行旋转，各列混合，轮钥异或。通过这些操作即可完成对称加密，即连续对数据进行一次加密和一次解密，会还原出数据本身。

用类似接口的语法表示如下：

```c++

template<std::size_t NKeyBits, std::size_t NRound>
class AES {
    AESMember<NKeyBits, NRound> member; 
public:
    using data_block_t = std::array<std::byte, 32>;
    using main_key_t = std::array<std::byte, NKeyBits / 8>;
    void initialize(const main_key_t& key) const noexcept;
    constexpr data_block_t encrypt(const data_block_t& input) const noexcept;
    constexpr data_block_t decrypt(const data_block_t& input) const noexcept;
};

```

## AES 的历史

AES 由比利时密码学家 Joan Daemen 和 Vincent Rijmen 设计，又称 Rijndael 加密法，于 2001 年 11 月 26 日由美国国家标准与技术研究院（NIST）发布于 FIPS PUB 197 文件，2002 年 5 月 26 日生效，旨在替代数据加密标准（DES）。

Rijndael 是由 Daemen 和 Rijmen 早期所设计的 Square 改良而来；而 Square 则是由 SHARK 发展而来。

不同于它的前任标准 DES，Rijndael使用的是置换-组合架构，而非 Feistel 架构。

严格地说， AES 和 Rijndael 加密法并不完全一样，因为 Rijndael 加密法可以支持更大范围的区块和密钥长度：AES 的区块长度固定为 128 位，密钥长度则可以是 128，192 或 256 位；而 Rijndael 使用的密钥和区块长度可以是 32 位的整数倍，以 128 位为下限， 256 位为上限。加密过程中使用的密钥是由 Rijndael 密钥生成方案产生。

- 参考[百度百科](https://baike.baidu.com/item/%E9%AB%98%E7%BA%A7%E5%8A%A0%E5%AF%86%E6%A0%87%E5%87%86/468774)。
- [FIPS PUB 197 官网归档文件](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)。
