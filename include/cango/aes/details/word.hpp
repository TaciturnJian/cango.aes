#ifndef INCLUDE_CANGO_AES_DETAILS_WORD
#define INCLUDE_CANGO_AES_DETAILS_WORD

#include <array>

#include "sbox.hpp"
#include "utils.hpp"

namespace cango::aes::details {

/// @brief 由四个字节组成的字
struct Word {
    static constexpr std::uint8_t byte_count = 4;
    using bytes_t = std::array<uint8_t, byte_count>;
    bytes_t bytes;

    static constexpr Word shift_left(const Word& origin, const std::uint8_t n) noexcept {
        Word result; // NOLINT(*-pro-type-member-init)
        for (std::uint8_t i = 0; i < byte_count; ++i)
            result.bytes[i] = origin.bytes[(i + n) % byte_count];
        return result;
    }

    static constexpr Word substitute_with(const Word& origin, const sbox_t& sbox) noexcept {
        Word result; // NOLINT(*-pro-type-member-init)
        for (std::uint8_t i = 0; i < byte_count; ++i)
            result.bytes[i] = sbox[origin.bytes[i]];
        return result;
    }

    /// @brief 将自己的每个字节向左循环移动 n 格
    void shift_left(const std::uint8_t n) noexcept {
        switch (n) {
        case 0:

            break;
        case 1: {
            const auto first_byte = bytes[0];
            for (std::uint8_t i = 0; i < 3; i++) { bytes[i] = bytes[i + 1]; }
            bytes[3] = first_byte;
            break;
        }
        case 2: {
            std::swap(bytes[0], bytes[2]);
            std::swap(bytes[1], bytes[3]);
            break;
        }
        case 3: {
            const auto last_byte = bytes[3];
            for (std::uint8_t i = 3; i > 0; i--) { bytes[i] = bytes[i - 1]; }
            bytes[0] = last_byte;
            break;
        }
        default:
            shift_left(n % 4);
        }
    }

    /// @brief 将自己的每个字节向右循环移动 n 格
    void shift_right(const std::uint8_t n) noexcept { shift_left(4 - (n % 4)); }

    /// @brief 使用替换盒替换每个字节
    void substitute_with(const sbox_t &sbox) noexcept { for (auto &byte: bytes) byte = sbox[byte]; }

    /// @brief 与另一个字按字节异或运算
    constexpr Word operator^(const Word &other) const noexcept {
        Word result{};
        for (std::uint8_t i = 0; i < byte_count; ++i) result.bytes[i] = bytes[i] ^ other.bytes[i];
        return result;
    }

    /// @brief 与另一个字按字节异或运算并赋值给自己
    constexpr Word &operator^=(const Word &other) noexcept {
        for (std::uint8_t i = 0; i < byte_count; ++i) { bytes[i] ^= other.bytes[i]; }
        return *this;
    }

    /// @brief 与轮常量异或
    constexpr Word &operator^=(const std::uint8_t rcon) noexcept {
        bytes[0] ^= rcon;
        return *this;
    }

    friend constexpr bool operator==(const Word& a, const Word& b) noexcept {
        return a.bytes == b.bytes;
    }

    friend constexpr bool operator!=(const Word& a, const Word& b) noexcept {
        return a.bytes != b.bytes;
    }
};

/// @brief 字列表
/// @tparam N 字数
template<std::size_t N>
struct WordArray {
    /// @brief 字数
    static constexpr auto word_count = N;
    static constexpr auto byte_count = word_count * 4;

    /// @brief 字列表类型
    using words_t = std::array<Word, word_count>;

    /// @brief 字列表
    words_t words;

    /// @brief 从字节列表得到字列表
    static constexpr WordArray from_array(const std::array<std::uint8_t, byte_count>& nums) noexcept {
        WordArray result;
        for (std::uint8_t i = 0; i < byte_count; ++i)
            result.words[i / 4].bytes[i % 4] = nums[i];
        return result;
    }

    /// @brief 将字列表转换为目标列表，便于一些操作
    /// @tparam T 目标类型
    /// @return 字列表作为目标类型列表的引用
    template<typename T>
    requires (sizeof(words_t) % sizeof(T) == 0)
    [[nodiscard]] std::array<T, sizeof(words_t) / sizeof(T)>& as_array() noexcept {
        return reinterpret_cast<std::array<T, sizeof(words_t) / sizeof(T)>&>(words);
    }

    /// @brief 将字列表转换为目标列表，便于一些操作
    /// @tparam T 目标类型
    /// @return 字列表作为目标类型列表的常量引用
    template<typename T>
    requires (sizeof(words_t) % sizeof(T) == 0)
    [[nodiscard]] const std::array<T, sizeof(words_t) / sizeof(T)>& as_array() const noexcept {
        return reinterpret_cast<const std::array<T, sizeof(words_t) / sizeof(T)>&>(words);
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_WORD
