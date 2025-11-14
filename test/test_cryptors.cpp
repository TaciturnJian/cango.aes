#include <span>

#include <cango/aes.hpp>
#include <cassert>

#include "toolbox.hpp"

using namespace cango::aes;
using namespace cango::aes::details;

template<typename TCryptor>
bool test_cryptor(const std::string_view name, const auto &plainText, const auto &key, const auto &expectedCipher) {
    const TCryptor cryptor{key};
    auto buffer = plainText;
    cryptor.encrypt(buffer);
    if (buffer != expectedCipher) {
        std::println(
            std::cerr,
            "[{}] 密文与预期不符：密文({})，预期({})",
            std::string(name),
            bytes_to_string(buffer),
            bytes_to_string(expectedCipher));
        return false;
    }

    cryptor.decrypt(buffer);
    if (buffer != plainText) {
        std::println(
            std::cerr,
            "[{}] 解密与原文不符：密文({})，原文({})",
            std::string(name),
            bytes_to_string(buffer),
            bytes_to_string(plainText));
        return false;
    }

    return true;
}

constexpr StateMatrix sm11(const std::uint8_t i, const std::uint8_t j) {
    StateMatrix result{};
    result.words[i].bytes[j] = 0x11;
    return result;
}

/// @brief AES-128 example from FIPS-197 Appendix C.1
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
bool test_aes128() {
    // plain_text: 00112233445566778899aabbccddeeff
    constexpr std::array<std::uint8_t, 16> plain_text = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    // key: 000102030405060708090a0b0c0d0e0f
    constexpr std::array<std::uint8_t, 16> key = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    };

    // expected_cipher 69c4e0d86a7b0430d8cdb78070b4c55a
    constexpr std::array<std::uint8_t, 16> expected_cipher = {
        0x69, 0xc4, 0xe0, 0xd8,
        0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80,
        0x70, 0xb4, 0xc5, 0x5a
    };

    constexpr auto key_mat = WordArray<4>::from_array(key);
    constexpr auto plain_text_mat = StateMatrix::from_array(plain_text);
    constexpr auto cipher_mat = StateMatrix::from_array(expected_cipher);
    constexpr auto round_keys = RoundKeys<10>::from_array<4>(key_mat);
    constexpr auto encrypted_mat = RoundKeys<10>::encrypt(round_keys, plain_text_mat);
    constexpr auto decrypted_mat = RoundKeys<10>::decrypt(round_keys, encrypted_mat);
    static_assert(encrypted_mat == cipher_mat, "failed: " "encrypted_mat == cipher_mat");
    static_assert(decrypted_mat == plain_text_mat, "failed: " "decrypted_mat == plain_text_mat");

    return test_cryptor<AES128Cryptor>("AES128", plain_text, key, expected_cipher);
}

/// @brief AES-192 example from FIPS-197 Appendix C.2
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
bool test_aes192() {
    // plain_text: 00112233445566778899aabbccddeeff
    constexpr std::array<std::uint8_t, 16> plain_text = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    // key: 000102030405060708090a0b0c0d0e0f1011121314151617
    constexpr std::array<std::uint8_t, 24> key = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17
    };

    // expected_cipher: dda97ca4864cdfe06eaf70a0ec0d7191
    constexpr std::array<std::uint8_t, 16> expected_cipher = {
        0xdd, 0xa9, 0x7c, 0xa4,
        0x86, 0x4c, 0xdf, 0xe0,
        0x6e, 0xaf, 0x70, 0xa0,
        0xec, 0x0d, 0x71, 0x91
    };

    constexpr auto key_mat = WordArray<6>::from_array(key);
    constexpr auto plain_text_mat = StateMatrix::from_array(plain_text);
    constexpr auto cipher_mat = StateMatrix::from_array(expected_cipher);
    constexpr auto round_keys = RoundKeys<12>::from_array<6>(key_mat);
    constexpr auto encrypted_mat = RoundKeys<12>::encrypt(round_keys, plain_text_mat);
    constexpr auto decrypted_mat = RoundKeys<12>::decrypt(round_keys, encrypted_mat);
    static_assert(encrypted_mat == cipher_mat, "failed: " "encrypted_mat == cipher_mat");
    static_assert(decrypted_mat == plain_text_mat, "failed: " "decrypted_mat == plain_text_mat");

    return test_cryptor<AES192Cryptor>("AES192", plain_text, key, expected_cipher);
}

/// @brief AES-192 example from FIPS-197 Appendix C.3
/// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
bool test_aes256() {
    // plain_text: 00112233445566778899aabbccddeeff
    constexpr std::array<std::uint8_t, 16> plain_text = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    // key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
    constexpr std::array<std::uint8_t, 32> key = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };

    // expected_cipher: 8ea2b7ca516745bfeafc49904b496089
    constexpr std::array<std::uint8_t, 16> expected_cipher = {
        0x8e, 0xa2, 0xb7, 0xca,
        0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90,
        0x4b, 0x49, 0x60, 0x89
    };

    constexpr auto key_mat = WordArray<8>::from_array(key);
    constexpr auto plain_text_mat = StateMatrix::from_array(plain_text);
    constexpr auto cipher_mat = StateMatrix::from_array(expected_cipher);
    constexpr auto round_keys = RoundKeys<14>::from_array<8>(key_mat);
    constexpr auto encrypted_mat = RoundKeys<14>::encrypt(round_keys, plain_text_mat);
    constexpr auto decrypted_mat = RoundKeys<14>::decrypt(round_keys, encrypted_mat);
    static_assert(encrypted_mat == cipher_mat, "failed: " "encrypted_mat == cipher_mat");
    static_assert(decrypted_mat == plain_text_mat, "failed: " "decrypted_mat == plain_text_mat");

    return test_cryptor<AES256Cryptor>("AES256", plain_text, key, expected_cipher);
}

void compile_example() {
    constexpr std::array<std::uint8_t, 16> main_key{/*主密钥, AES128 规定主密钥有 128 二进制位*/};
    constexpr std::array<std::uint8_t, 16> plain {/*原文*/};

    // 编译时加密解密
    constexpr auto const_cryptor = AES128Cryptor::create_const(main_key);
    constexpr auto encrypted = AES128Cryptor::encrypt(const_cryptor, plain);
    constexpr auto decrypted = AES128Cryptor::decrypt(const_cryptor, encrypted);
    static_assert(decrypted == plain, "failed: " "decrypted == plain");

    // 运行时加密解密
    const AES128Cryptor cryptor{main_key};//初始化工具
    auto buffer = plain;
    cryptor.encrypt(buffer);
    cryptor.decrypt(buffer);
    assert(buffer == plain);
}

int main() {
    compile_example();

    toolbox tb{true};
    tb.execute("aes128", test_aes128);
    tb.execute("aes192", test_aes192);
    tb.execute("aes256", test_aes256);
    tb.summary();
    return tb.failed > 0 ? 1 : 0;
}
