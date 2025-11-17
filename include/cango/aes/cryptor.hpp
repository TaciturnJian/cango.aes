#ifndef INCLUDE_CANGO_AES_CRYPTOR
#define INCLUDE_CANGO_AES_CRYPTOR

#include "details/key.hpp"

namespace cango::aes {

/// @brief AES 密码工具，包含加密和解密功能，需要使用主钥初始化
template<std::size_t NWord, std::size_t NRound>
class Cryptor {
    /// @brief 轮密钥列表
    details::RoundKeys<NRound> keys{};

public:
    /// @brief 暴露轮密钥为公开成员的 AES 密码工具
    struct BareCryptor {
        details::RoundKeys<NRound> keys;
    };

    /// @brief 默认构造函数，不执行任何操作
    constexpr Cryptor() noexcept = default;

    explicit Cryptor(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        reinit(mainKey);
    }

    /// @brief 使用主钥重新初始化上下文
    void reinit(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        keys.expand_from(reinterpret_cast<const details::WordArray<NWord>&>(mainKey));
    }

    /// @brief 加密数据
    void encrypt(std::array<std::uint8_t, 4 * 4>& data) const noexcept {
        keys.encrypt(reinterpret_cast<details::StateMatrix&>(data));
    }

    static constexpr BareCryptor create_const(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        const auto main_key = details::WordArray<NWord>::from_array(mainKey);
        return {details::RoundKeys<NRound>::from_array(main_key)};
    }

    /// @brief 加密数据
    static constexpr std::array<std::uint8_t, 4 * 4> encrypt(
        const BareCryptor& cryptor,
        const std::array<std::uint8_t, 4 * 4>& data
        ) noexcept {
        const auto input_mat = details::StateMatrix::from_array(data);
        const auto output_mat = details::RoundKeys<NRound>::encrypt(cryptor.keys, input_mat);
        return details::StateMatrix::to_array(output_mat);
    }

    /// @brief 解密数据
    void decrypt(std::array<std::uint8_t, 4 * 4>& data) const noexcept {
        keys.decrypt(reinterpret_cast<details::StateMatrix&>(data));
    }

    /// @brief 解密数据
    static constexpr std::array<std::uint8_t, 4 * 4> decrypt(
        const BareCryptor& cryptor,
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
