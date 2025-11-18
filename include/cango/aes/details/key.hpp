#ifndef INCLUDE_CANGO_AES_DETAILS_KEY
#define INCLUDE_CANGO_AES_DETAILS_KEY

#include <array>

#include "matrix.hpp"
#include "word.hpp"

namespace cango::aes::details {

/// @brief 轮密钥列表，从主密钥扩展而来，包含加密和解密所需的所有轮密钥
template<std::size_t NRound>
struct RoundKeys {
    /// @brief 标准定义的轮数
    static constexpr auto round_count = NRound;

    /// @brief 轮密钥数
    static constexpr auto key_count = round_count + 1;

    /// @brief 轮密钥列表的字数
    static constexpr auto word_count = 4 * key_count;

    /// @brief 状态列表
    std::array<StateMatrix, key_count> states;

    /// @brief 访问目标字
    /// @param index 目标下标
    /// @warning 不检查越界
    [[nodiscard]] constexpr Word &at_word(const std::size_t index) noexcept {
        return states[index / 4].words[index % 4];
    }

    /// @brief 访问目标字
    /// @param index 目标下标
    /// @warning 不检查越界
    [[nodiscard]] constexpr const Word &at_word(const std::size_t index) const noexcept {
        return states[index / 4].words[index % 4];
    }

    /// @brief 从字列表主钥展开轮钥
    /// @param mainKey 主钥
    /// @return 轮钥
    static constexpr RoundKeys from_array(const auto& mainKey) {
        RoundKeys result;
        result.expand_from(mainKey);
        return result;
    }

    template<std::size_t NWord>
    constexpr void expand_rest() {
        auto i = NWord;
        RoundConstant round_constant{};
        for (; i < word_count; ++i) {
            auto temp = at_word(i - 1);
            if (i % NWord == 0) {
                const auto first_byte = temp[0]; // rotate and sbox
                for (std::uint8_t j = 0; j < 3; ++j)
                    temp[j] = SBox[temp[j + 1]];
                temp[3] = SBox[first_byte];
                temp[0] ^= round_constant.step();
            }
            else if (NWord > 6 && i % NWord == 4) SBox.substitute(temp);
            at_word(i) = at_word(i - NWord) ^ temp;
        }
    }

    /// @brief 从主密钥扩展得到轮密钥
    /// @tparam NWord 主密钥字数
    /// @param mainKey 主密钥数据
    template<std::size_t NWord>
    constexpr void expand_from(const std::array<Word, NWord>& mainKey) {
        for (std::size_t i = 0; i < NWord; ++i)
            at_word(i) = mainKey[i];
        expand_rest<NWord>();
    }

    /// @brief 从主密钥扩展得到轮密钥
    /// @tparam NBytes 主密钥字节数
    /// @param mainKey 主密钥数据
    template<std::size_t NBytes>
    constexpr void expand_from(const std::array<std::uint8_t, NBytes>& mainKey) {
        constexpr auto NWord = NBytes / 4;
        for (std::size_t i = 0; i < NWord; ++i) {
            auto& bytes = at_word(i);
            for (std::uint8_t j = 0; j < 4; ++j)
                bytes[j] = mainKey[i * 4 + j];
        }
        expand_rest<NWord>();
    }

    /// @brief 使用轮密钥加密数据，直接在原矩阵上操作
    /// @param origin 需要加密的数据状态矩阵
    constexpr void encrypt(StateMatrix &origin) const noexcept {
        origin.add_round_key_inplace(states[0]);
        for (std::size_t round = 1; round < NRound; ++round) {
            origin.substitute_with_inplace(SBox);
            origin.shift_rows_inplace();
            origin.mix_columns_inplace(CMDSMatrix);
            origin.add_round_key_inplace(states[round]);
        }
        origin.substitute_with_inplace(SBox);
        origin.shift_rows_inplace();
        origin.add_round_key_inplace(states[NRound]);
    }

    constexpr void encrypt(std::array<std::uint8_t, 16>& origin) const noexcept {
        auto mat = StateMatrix::from_array(origin);
        encrypt(mat);
        origin = StateMatrix::to_array(mat);
    }

    /// @brief 使用轮密钥加密数据
    /// @param origin 原数据矩阵
    /// @return 加密后的数据矩阵
    [[nodiscard]] constexpr StateMatrix encrypt(const StateMatrix& origin) const noexcept {
        auto result = origin;
        encrypt(result);
        return result;
    }

    /// @brief 使用轮密钥接解密数据，直接在原矩阵上操作
    /// @param origin 需要解密的数据状态矩阵
    constexpr void decrypt(StateMatrix &origin) const noexcept {
        origin.add_round_key_inplace(states[NRound]);
        for (auto round = NRound - 1; round > 0; --round) {
            origin.inv_shift_rows_inplace();
            origin.substitute_with_inplace(InvSBox);
            origin.add_round_key_inplace(states[round]);
            origin.mix_columns_inplace(InvCMDSMatrix);
        }
        origin.inv_shift_rows_inplace();
        origin.substitute_with_inplace(InvSBox);
        origin.add_round_key_inplace(states[0]);
    }

    /// @brief 使用轮密钥接解密数据
    /// @param origin 原数据矩阵
    /// @return 解密后的数据矩阵
    [[nodiscard]] constexpr StateMatrix decrypt(const StateMatrix& origin) const noexcept {
        auto result = origin;
        decrypt(result);
        return result;
    }

    constexpr void decrypt(std::array<std::uint8_t, 16>& origin) const noexcept {
        auto mat = StateMatrix::from_array(origin);
        decrypt(mat);
        origin = StateMatrix::to_array(mat);
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_KEY
