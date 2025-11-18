# cango.aes ：仅头文件的 C++20 AES 实现

## 特点(feature)

- 内部无动态内存分配，使用 `std::array` 完成密钥准备工作
- 简单易懂的对象封装
- 支持编译时加密解密
- 适合个人学习 AES 或造轮子

## 例子(example)

提供了：
- `cango::aes::AES128Cryptor`
- `cango::aes::AES192Cryptor`
- `cango::aes::AES256Cryptor`

指定主钥和 16 字节字块后可进行加密解密：

```c++
constexpr std::array<std::uint8_t, 16> main_key{/*主密钥, AES128 规定主密钥有 128 二进制位*/};
constexpr std::array<std::uint8_t, 16> plain {/*原文*/};

//初始化工具
constexpr AES128Cryptor cryptor{main_key};

// 编译时加密解密
constexpr auto encrypted = cryptor.encrypt(plain);
constexpr auto decrypted = cryptor.decrypt(encrypted);
static_assert(decrypted == plain, "failed: " "decrypted == plain");

// 运行时加密解密
auto buffer = plain;
cryptor.encrypt(buffer);
cryptor.decrypt(buffer);
assert(buffer == plain);
```

## 参考(reference)

- [AES128 标准PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES库](https://github.com/SergeyBel/AES)
