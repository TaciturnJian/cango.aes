#ifndef INCLUDE_CANGO_AES_DETAILS_UTILS
#define INCLUDE_CANGO_AES_DETAILS_UTILS

#include <cstdint>

namespace cango::aes::details {

/// @brief AES 的标准信息
struct StandardInfo {
    /// @brief 字数，描述一个标准的密钥由多少个字组成。一个字由 4 个字节组成。一个字节为 8 位二进制数。
    std::uint8_t main_key_word_count;

    /// @brief 轮数，描述一个标准的加密过程需要进行多少轮变换。
    std::uint8_t round_count;
};

/// @brief AES-128 标准信息
constexpr StandardInfo AES128{4, 10};

/// @brief AES-192 标准信息
constexpr StandardInfo AES192{6, 12};

/// @brief AES-256 标准信息
constexpr StandardInfo AES256{8, 14};

/// @brief 在 GF(2^8) 上进行 xtime 运算
[[nodiscard]] constexpr std::uint8_t xtime(const std::uint8_t x) noexcept {
    return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
}

/// @brief 在 GF(2^8) 上进行乘法运算
[[nodiscard]] constexpr std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b) noexcept {
    std::uint8_t result = 0;
    while (b) {
        if (b & 1) result ^= a;
        const auto hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return result;
}

/// @brief 轮常数
struct RoundConstant {
    /// @brief 轮常数的值
    std::uint8_t value{1};

    /// @brief 进行一步计算，返回计算之前的值
    constexpr std::uint8_t step() noexcept {
        const auto old = value;
        value = xtime(value);
        return old;
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_UTILS
