#ifndef INCLUDE_CANGO_AES_DETAILS_KEY
#define INCLUDE_CANGO_AES_DETAILS_KEY

#include <span>

#include "matrix.hpp"

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
    [[nodiscard]] constexpr Word &at_word(const std::size_t index) noexcept {
        return states[index / 4].words[index % 4];
    }

    /// @brief 访问目标字
    /// @param index 目标下标
    [[nodiscard]] constexpr const Word &at_word(const std::size_t index) const noexcept {
        return states[index / 4].words[index % 4];
    }

    /// @brief 从主密钥扩展得到轮密钥
    /// @tparam NWord 主密钥字数
    /// @param mainKey 主密钥数据
    template<std::size_t NWord>
    void expand_from(const std::span<const Word, NWord> mainKey) {
        std::size_t i = 0;
        for (const auto &word: mainKey) at_word(i++) = word;

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

    template<std::size_t NWord>
    void expand_from(const std::array<Word, NWord>& mainKey) {
        expand_from(std::span<const Word, NWord>{mainKey});
    }

    template<std::size_t NWord>
    void expand_from(const WordArray<NWord>& mainKey) {
        expand_from(mainKey.words);
    }

    /// @brief 使用轮密钥列表对数据进行加密
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

    /// @brief 使用轮密钥列表对数据进行加密
    /// @param origin 需要加密的数据
    void encrypt(const std::span<std::uint8_t, 16> &origin) const noexcept {
        encrypt(*reinterpret_cast<StateMatrix*>(origin.data()));
    }

    /// @brief 使用轮密钥列表对数据进行解密
    /// @param origin 需要解密的数据状态矩阵
    void decrypt(StateMatrix &origin) const noexcept {
        origin.add_round_key(states[NRound]);
        for (std::size_t round = NRound - 1; round > 0; --round) {
            origin.inv_shift_rows();
            origin.substitute_with(InvSBox);
            origin.add_round_key(states[round]);
            origin.mix_columns(InvCMDSMatrix);
        }
        origin.inv_shift_rows();
        origin.substitute_with(InvSBox);
        origin.add_round_key(states[0]);
    }

    /// @brief 使用轮密钥列表对数据进行解密
    /// @param origin 需要解密的数据
    void decrypt(const std::span<std::uint8_t, 16> &origin) const noexcept {
        decrypt(*reinterpret_cast<StateMatrix*>(origin.data()));
    }
};

}

#endif//INCLUDE_CANGO_AES_DETAILS_KEY
