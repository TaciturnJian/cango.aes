# cango.aes ：仅头文件的 C++20 AES 实现

个人学习造轮子。

参考：
- [AES128 标准PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [AES库](https://github.com/SergeyBel/AES)

提供了：
- `cango::aes::AES128Cryptor`
- `cango::aes::AES192Cryptor`
- `cango::aes::AES256Cryptor`

指定主钥和 16 字节字块后可进行加密解密：

```c++
std::array<std::uint8_t, 16> main_key{/*主密钥, AES128 规定主密钥有 128 二进制位*/};
const AES128Cryptor cryptor{main_key};//初始化工具

std::array<std::uint8_t, 16> buffer0{/*原文*/};
std::array<std::uint8_t, 16> buffer1{/*原文*/};

// 使用工具加密解密
cryptor.encrypt(buffer0);
cryptor.encrypt(buffer1);
cryptor.decrypt(buffer0);
cryptor.decrypt(buffer1);
```
