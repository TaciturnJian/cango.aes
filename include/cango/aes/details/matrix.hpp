#ifndef INCLUDE_CANGO_AES_DETAILS_MATRIX
#define INCLUDE_CANGO_AES_DETAILS_MATRIX

#include <array>
#include <cstdint>

#include "sbox.hpp"
#include "word.hpp"

namespace cango::aes::details {

/// @brief 状态矩阵，4行4列的字节矩阵，一个字一列
struct StateMatrix {
    /// @brief 字列表
    std::array<std::array<std::uint8_t, 4>, 4> words;

    /// @brief 从字节列表转换得到状态矩阵
    /// @param nums 字节列表，将会按列存入状态矩阵
    /// @return 与字节列表元素一一对应的状态矩阵
    static constexpr StateMatrix from_array(const std::array<std::uint8_t, 16> &nums) noexcept {
        StateMatrix result{};
        for (std::uint8_t i = 0; i < 4; ++i)
            for (std::uint8_t j = 0; j < 4; ++j) result.words[i][j] = nums[i * 4 + j];
        return result;
    }

    /// @brief 将状态矩阵转换为字节列表
    /// @param matrix 状态矩阵，将会按列存入字节列表
    /// @return 与状态矩阵元素一一对应的字节列表
    static constexpr std::array<std::uint8_t, 16> to_array(const StateMatrix &matrix) noexcept {
        std::array<std::uint8_t, 16> result{};
        for (std::uint8_t i = 0; i < 4; ++i)
            for (std::uint8_t j = 0; j < 4; ++j) result[i * 4 + j] = matrix.words[i][j];
        return result;
    }

    /// @brief 行移位操作
    /// @return 行移位后的状态矩阵
    [[nodiscard]] constexpr StateMatrix shift_rows() const noexcept {
        // (row, col) after shift rows (row', col')
        // col 0      1      2      3  row
        // (0, 0) (0, 1) (0, 2) (0, 3)  0
        // (1, 1) (1, 2) (1, 3) (1, 0)  1
        // (2, 2) (2, 3) (2, 0) (2, 1)  2
        // (3, 3) (3, 0) (3, 1) (3, 2)  3
        // row' = row
        // col' = (col + row) % 4

        StateMatrix result{};
        for (std::uint8_t col = 0; col < 4; ++col)
            for (std::uint8_t row = 0; row < 4; ++row) result.words[col][row] = words[(col + row) % 4][row];
        return result;
    }

    /// @brief 逆行移位操作
    /// @return 逆行移位的状态矩阵
    [[nodiscard]] constexpr StateMatrix inv_shift_rows() const noexcept {
        // (row, col) after inv shift rows
        // col 0      1      2      3  row
        // (0, 0) (0, 1) (0, 2) (0, 3)  0
        // (1, 3) (1, 0) (1, 1) (1, 2)  1
        // (2, 2) (2, 3) (2, 0) (2, 1)  2
        // (3, 1) (3, 2) (3, 3) (3, 0)  3
        // row' = row
        // col' = ( 4 + col - row ) % 4
        StateMatrix result{};
        for (std::uint8_t col = 0; col < 4; ++col)
            for (std::uint8_t row = 0; row < 4; ++
                 row) result.words[col][row] = words[(4 + col - row) % 4][row];
        return result;
    }

    /// @brief 字节替换操作
    /// @param sbox 替换盒
    /// @return 字节替换后的状态矩阵
    [[nodiscard]] constexpr StateMatrix substitute_with(const SubstituteBox &sbox) const noexcept {
        StateMatrix result{};
        for (std::uint8_t i = 0; i < 4; ++i)
            for (std::uint8_t j = 0; j < 4; ++j) result.words[i][j] = sbox[words[i][j]];
        return result;
    }

    /// @brief 列混合操作
    /// @param mds MDS 矩阵
    [[nodiscard]] constexpr StateMatrix mix_columns(const mds_t &mds) const noexcept {
        StateMatrix result{};
        for (std::uint8_t col = 0; col < 4; ++col)
            for (std::uint8_t i = 0; i < 4; ++i)
                for (std::uint8_t j = 0; j < 4; ++j) result.words[col][i] ^= gf_mul(mds[i * 4 + j],
                                                         words[col][j]);
        return result;
    }

    /// @brief 轮异或操作
    /// @param key 轮密钥
    /// @return 操作结果状态矩阵
    [[nodiscard]] constexpr StateMatrix add_round_key(const StateMatrix &key) const noexcept {
        StateMatrix result{};
        for (std::uint8_t i = 0; i < 4; ++i)
            for (std::uint8_t j = 0; j < 4; ++j) result.words[i][j] = words[i][j] ^ key.words[i][j];
        return result;
    }

    /// @brief 单行移位操作
    constexpr void shift_row_inplace(const std::uint8_t row, const std::uint8_t offset) noexcept {
        if (offset == 1) {
            const auto first_byte = words[0][row];
            for (std::uint8_t i = 0; i < 3; ++i) words[i][row] = words[i + 1][row];
            words[3][row] = first_byte;
        }
        else if (offset == 2) {
            std::swap(words[0][row], words[2][row]);
            std::swap(words[1][row], words[3][row]);
        }
        else if (offset == 3) {
            const auto last_byte = words[3][row];
            for (std::uint8_t i = 3; i > 0; --i) words[i][row] = words[i - 1][row];
            words[0][row] = last_byte;
        }
    }

    /// @brief 行移位操作
    constexpr void shift_rows_inplace() { for (std::uint8_t row = 1; row < 4; ++row) shift_row_inplace(row, row); }

    /// @brief 逆行移位操作
    constexpr void inv_shift_rows_inplace() {
        for (std::uint8_t row = 1; row < 4; ++row) shift_row_inplace(row, 4 - row);
    }

    /// @brief 字节替换操作
    /// @param sbox 替换盒，使用逆替换盒操作与使用正替换盒是互逆的
    constexpr void substitute_with_inplace(const SubstituteBox &sbox) {
        for (auto &bytes: words) for (auto &byte: bytes) byte = sbox[byte];
    }

    /// @brief 列混合操作
    /// @param mds MDS 矩阵，使用逆 MDS 矩阵操作与使用正 MDS 矩阵是互逆的
    constexpr void mix_columns_inplace(const mds_t &mds) {
        StateMatrix tmp{};
        for (std::uint8_t col = 0; col < 4; ++col)
            for (std::uint8_t i = 0; i < 4; ++i)
                for (std::uint8_t j = 0; j < 4; ++j) tmp.words[col][i] ^= gf_mul(mds[i * 4 + j],
                                                         words[col][j]);
        words = tmp.words;
    }

    /// @brief 轮异或操作
    /// @param key 轮密钥
    constexpr void add_round_key_inplace(const StateMatrix &key) noexcept {
        for (std::uint8_t i = 0; i < 4; ++i) for (
            std::uint8_t j = 0; j < 4; ++j) words[i][j] ^= key.words[i][j];
    }

    /// @brief 比较每个状态，判断是否相等
    friend constexpr bool operator==(const StateMatrix &lhs, const StateMatrix &rhs) noexcept {
        return lhs.words == rhs.words;
    }

    /// @brief 比较每个状态，判断是否相等
    friend constexpr bool operator!=(const StateMatrix &lhs, const StateMatrix &rhs) noexcept {
        return lhs.words != rhs.words;
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_MATRIX
