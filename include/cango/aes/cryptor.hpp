#ifndef INCLUDE_CANGO_AES_CRYPTOR
#define INCLUDE_CANGO_AES_CRYPTOR

#include <span>

#include "details/key.hpp"

namespace cango::aes {

/// @brief AES 上下文，包含加密和解密功能
template<std::size_t NWord, std::size_t NRound>
class Cryptor {
    /// @brief 轮密钥列表
    details::RoundKeys<NRound> keys{};

public:
    struct ConstCryptor {
        details::RoundKeys<NRound> keys;
    };

    /// @brief 默认构造函数，不执行任何操作
    constexpr Cryptor() noexcept = default;

    /// @brief 使用主钥初始化上下文
    explicit Cryptor(const std::span<const std::uint8_t, NWord * 4> mainKey) noexcept {
        reinit(mainKey);
    }

    /// @brief 使用主钥重新初始化上下文
    void reinit(const std::span<const std::uint8_t, NWord * 4> mainKey) noexcept {
        keys.expand_from(*reinterpret_cast<const details::WordArray<NWord>*>(mainKey.data()));
    }

    /// @brief 加密数据
    void encrypt(const std::span<std::uint8_t, 4 * 4> data) const noexcept { keys.encrypt(data); }

    static constexpr ConstCryptor create_const(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        const auto main_key = details::WordArray<NWord>::from_array(mainKey);
        return {details::RoundKeys<NRound>::from_array(main_key)};
    }

    /// @brief 加密数据
    static constexpr std::array<std::uint8_t, 4 * 4> encrypt(
        const ConstCryptor& cryptor,
        const std::array<std::uint8_t, 4 * 4>& data
        ) noexcept {
        const auto input_mat = details::StateMatrix::from_array(data);
        const auto output_mat = details::RoundKeys<NRound>::encrypt(cryptor.keys, input_mat);
        return details::StateMatrix::to_array(output_mat);
    }

    /// @brief 解密数据
    void decrypt(const std::span<std::uint8_t, 4 * 4> data) const noexcept { keys.decrypt(data); }

    /// @brief 解密数据
    static constexpr std::array<std::uint8_t, 4 * 4> decrypt(
        const ConstCryptor& cryptor,
        const std::array<std::uint8_t, 4 * 4>& data
        ) noexcept {
        const auto input_mat = details::StateMatrix::from_array(data);
        const auto output_mat = details::RoundKeys<NRound>::decrypt(cryptor.keys, input_mat);
        return details::StateMatrix::to_array(output_mat);
    }
};

/// @brief AES-128 密码工具，指定 128 二进制位(16字节)密钥后可用于加密和解密 128 二进制位(16字节)数据
using AES128Cryptor = Cryptor<4, 10>;

/// @brief AES-192 密码工具，指定 192 二进制位(24字节)密钥后可用于加密和解密 128 二进制位(16字节)数据
using AES192Cryptor = Cryptor<6, 12>;

/// @brief AES-256 密码工具，指定 256 二进制位(32字节)密钥后可用于加密和解密 128 二进制位(16字节)数据
using AES256Cryptor = Cryptor<8, 14>;

}

#endif//INCLUDE_CANGO_AES_CRYPTOR
