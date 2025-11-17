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

    /// @brief 状态列表类型，每个轮密钥实际上就是一个状态矩阵
    using states_t = std::array<StateMatrix, key_count>;

    /// @brief 状态列表
    states_t states;

    /// @brief 将轮密钥转换为列表，便于一些操作
    /// @tparam T 目标类型
    /// @return 轮密钥作为目标类型列表的引用
    template<typename T>
    requires (sizeof(states_t) % sizeof(T) == 0)
    [[nodiscard]] std::array<T, sizeof(states_t) / sizeof(T)>& as_array() noexcept {
        return reinterpret_cast<std::array<T, sizeof(states_t) / sizeof(T)>&>(states);
    }

    /// @brief 将轮密钥转换为列表，便于一些操作
    /// @tparam T 目标类型
    /// @return 轮密钥作为目标类型列表的常量引用
    template<typename T>
    requires (sizeof(states_t) % sizeof(T) == 0)
    [[nodiscard]] const std::array<T, sizeof(states_t) / sizeof(T)>& as_array() const noexcept {
        return reinterpret_cast<const std::array<T, sizeof(states_t) / sizeof(T)>&>(states);
    }

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
    template<std::size_t NWord>
    static constexpr RoundKeys from_array(const WordArray<NWord>& mainKey) {
        RoundKeys result;
        std::size_t i = 0;
        for (const auto &word: mainKey.words)
            result.at_word(i++) = word;

        RoundConstant rcon{};
        for (; i < word_count; ++i) {
            auto temp = result.at_word(i - 1);
            if (i % NWord == 0) {
                temp = Word::shift_left(temp, 1);
                temp = Word::substitute_with(temp, SBox);
                temp ^= rcon.step();
            }
            else if (NWord > 6 && i % NWord == 4) {
                temp = Word::substitute_with(temp, SBox);
            }
            result.at_word(i) = result.at_word(i - NWord) ^ temp;
        }
        return result;
    }

    /// @brief 使用轮密钥列表对数据进行加密
    /// @param key 轮密钥
    /// @param origin 需要加密的数据状态矩阵
    static constexpr StateMatrix encrypt(const RoundKeys& key, const StateMatrix& origin) {
        auto result = StateMatrix::add_round_key(origin, key.states[0]);
        for (std::size_t round = 1; round < NRound; ++round) {
            result = StateMatrix::substitute_with(result, SBox);
            result = StateMatrix::shift_rows(result);
            result = StateMatrix::mix_columns(result, CMDSMatrix);
            result = StateMatrix::add_round_key(result, key.states[round]);
        }
        result = StateMatrix::substitute_with(result, SBox);
        result = StateMatrix::shift_rows(result);
        result = StateMatrix::add_round_key(result, key.states[NRound]);
        return result;
    }

    /// @brief 使用轮密钥列表对数据进行解密，直接在原矩阵上操作
    /// @param key 轮密钥
    /// @param origin 需要解密的数据状态矩阵
    static constexpr StateMatrix decrypt(const RoundKeys& key, const StateMatrix& origin) noexcept {
        auto result = StateMatrix::add_round_key(origin, key.states[NRound]);
        for (auto round = NRound - 1; round > 0; --round) {
            result = StateMatrix::inv_shift_rows(result);
            result = StateMatrix::substitute_with(result, InvSBox);
            result = StateMatrix::add_round_key(result, key.states[round]);
            result = StateMatrix::mix_columns(result, InvCMDSMatrix);
        }
        result = StateMatrix::inv_shift_rows(result);
        result = StateMatrix::substitute_with(result, InvSBox);
        result = StateMatrix::add_round_key(result, key.states[0]);
        return result;
    }

    /// @brief 从主密钥扩展得到轮密钥
    /// @tparam NWord 主密钥字数
    /// @param mainKey 主密钥数据
    template<std::size_t NWord>
    void expand_from(const WordArray<NWord>& mainKey) {
        std::size_t i = 0;
        for (const auto &word: mainKey.words) at_word(i++) = word;

        RoundConstant round_constant{};
        for (; i < word_count; ++i) {
            auto temp = at_word(i - 1);
            if (i % NWord == 0) {
                temp.shift_left(1);
                temp.substitute_with(SBox);
                temp ^= round_constant.step();
            }
            else if (NWord > 6 && i % NWord == 4) { temp.substitute_with(SBox); }
            at_word(i) = at_word(i - NWord) ^ temp;
        }
    }

    /// @brief 使用轮密钥列表对数据进行加密，直接在原矩阵上操作
    /// @param origin 需要加密的数据状态矩阵
    void encrypt(StateMatrix &origin) const noexcept {
        origin.add_round_key(states[0]);
        for (std::size_t round = 1; round < NRound; ++round) {
            origin.substitute_with(SBox);
            origin.shift_rows();
            origin.mix_columns(CMDSMatrix);
            origin.add_round_key(states[round]);
        }
        origin.substitute_with(SBox);
        origin.shift_rows();
        origin.add_round_key(states[NRound]);
    }

    /// @brief 使用轮密钥列表对数据进行解密，直接在原矩阵上操作
    /// @param origin 需要解密的数据状态矩阵
    void decrypt(StateMatrix &origin) const noexcept {
        origin.add_round_key(states[NRound]);
        for (auto round = NRound - 1; round > 0; --round) {
            origin.inv_shift_rows();
            origin.substitute_with(InvSBox);
            origin.add_round_key(states[round]);
            origin.mix_columns(InvCMDSMatrix);
        }
        origin.inv_shift_rows();
        origin.substitute_with(InvSBox);
        origin.add_round_key(states[0]);
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_KEY
