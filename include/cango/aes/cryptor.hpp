#ifndef INCLUDE_CANGO_AES_CRYPTOR
#define INCLUDE_CANGO_AES_CRYPTOR

#include "details/key.hpp"

namespace cango::aes {

/// @brief AES 标准
struct Standard {
    /// @brief 主钥的二进制位数
    std::size_t key_bits;

    /// @brief 运算轮数
    std::size_t rounds;
};

/// @brief AES-128 标准
inline constexpr Standard AES128 {128, 10};

/// @brief AES-192 标准
inline constexpr Standard AES192 {192, 12};

/// @brief AES-256 标准
inline constexpr Standard AES256 {256, 14};

/// @brief 数据块的类型，为 4 * 4 字节列表
using block_t = std::array<std::uint8_t, 4 * 4>;

/// @brief AES 密码工具，包含加密和解密功能，需要使用主钥初始化
template<std::size_t NWord, std::size_t NRound>
class Cryptor {
    /// @brief 轮密钥列表
    details::RoundKeys<NRound> keys{};

public:
    /// @brief 暴露轮密钥为公开成员的 AES 密码工具
    struct BareCryptor {
        details::RoundKeys<NRound> keys;

        /// @brief 加密数据
        [[nodiscard]] constexpr block_t encrypt(const block_t& data) const noexcept {
            const auto input_mat = details::StateMatrix::from_array(data);
            const auto output_mat = keys.encrypt(input_mat);
            return details::StateMatrix::to_array(output_mat);
        }

        /// @brief 解密数据
        [[nodiscard]] constexpr block_t decrypt(const block_t& data) const noexcept {
            const auto input_mat = details::StateMatrix::from_array(data);
            const auto output_mat = keys.decrypt(input_mat);
            return details::StateMatrix::to_array(output_mat);
        }
    };

    /// @brief 默认构造函数，不执行任何操作
    constexpr Cryptor() noexcept = default;

    /// @brief 使用指定的主钥初始化密码工具
    explicit constexpr Cryptor(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        reinit(mainKey);
    }

    /// @brief 使用主钥重新初始化上下文
    constexpr void reinit(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        keys.expand_from(mainKey);
    }

    /// @brief 加密数据
    constexpr void encrypt(block_t& data) const noexcept {
        keys.encrypt(data);
    }

    [[nodiscard]] constexpr block_t encrypt(const auto& data) const noexcept {
        auto result = data;
        encrypt(result);
        return result;
    }

    /// @brief 解密数据
    constexpr void decrypt(block_t& data) const noexcept {
        keys.decrypt(data);
    }

    [[nodiscard]] constexpr block_t decrypt(const auto& data) const noexcept {
        auto result = data;
        decrypt(result);
        return result;
    }

    static constexpr BareCryptor create_const(const std::array<std::uint8_t, NWord * 4>& mainKey) noexcept {
        return {details::RoundKeys<NRound>::from_array(mainKey)};
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
