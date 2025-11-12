#ifndef INCLUDE_CANGO_AES_DETAILS_MATRIX
#define INCLUDE_CANGO_AES_DETAILS_MATRIX

#include "sbox.hpp"
#include "word.hpp"

namespace cango::aes::details {

/// @brief mds 矩阵类型
using mds_t = std::array<std::uint8_t, 16>;

/// Circulant MDS Matrix ，循环 MDS 矩阵，用于状态矩阵的列混合
constexpr mds_t CMDSMatrix = {
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2
};

/// Inverse circulant MDS matrix ，逆循环 MDS 矩阵，用于状态矩阵的逆列混合
constexpr mds_t InvCMDSMatrix = {
    14, 11, 13, 9,
    9, 14, 11, 13,
    13, 9, 14, 11,
    11, 13, 9, 14
};

/// @brief 状态矩阵，4行4列的字节矩阵，一个字一列
struct StateMatrix : WordArray<4> {
    /// @brief 单行移位操作
    template<std::uint8_t Offset>
    void shift_row(const std::uint8_t row) noexcept {
        JumpIndexer<std::uint8_t, 4> indexer{words[0].bytes.data() + row};
        if constexpr (Offset == 1) {
            const auto first_byte = indexer[0];
            for (std::uint8_t i = 0; i < 3; i++) { indexer[i] = indexer[i + 1]; }
            indexer[3] = first_byte;
        }
        else if constexpr (Offset == 2) {
            std::swap(indexer[0], indexer[2]);
            std::swap(indexer[1], indexer[3]);
        }
        else if constexpr (Offset == 3) {
            const auto last_byte = indexer[3];
            for (std::uint8_t i = 3; i > 0; i--) { indexer[i] = indexer[i - 1]; }
            indexer[0] = last_byte;
        }
    }

    /// @brief 行移位操作
    void shift_rows() {
        shift_row<1>(1);
        shift_row<2>(2);
        shift_row<3>(3);
    }

    /// @brief 逆行移位操作
    void inv_shift_rows() {
        shift_row<1>(3);
        shift_row<2>(2);
        shift_row<3>(1);
    }

    /// @brief 字节替换操作
    /// @param sbox 替换盒，使用逆替换盒操作与使用正替换盒是互逆的
    void substitute_with(const sbox_t &sbox) { for (auto &[bytes]: words) for (auto &byte: bytes) byte = sbox[byte]; }

    /// @brief 列混合操作
    /// @param mds MDS 矩阵，使用逆 MDS 矩阵操作与使用正 MDS 矩阵是互逆的
    void mix_columns(const mds_t &mds) {
        StateMatrix tmp{};
        for (std::uint8_t col = 0; col < 4; ++col) {
            for (std::uint8_t i = 0; i < 4; ++i) {
                for (std::uint8_t j = 0; j < 4; ++j) {
                    tmp.words[col].bytes[i] ^= gf_mul(mds[i * 4 + j], words[col].bytes[j]);
                }
            }
        }
        words = tmp.words;
    }

    /// @brief 轮异或操作
    /// @param key 轮密钥
    void add_round_key(const StateMatrix &key) noexcept {
        for (std::uint8_t i = 0; i < 4; ++i) { words[i] ^= key.words[i]; }
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_MATRIX
