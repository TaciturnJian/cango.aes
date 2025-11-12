#include <span>

#include <cango/aes.hpp>

#include "toolbox.hpp"

using namespace cango::aes;

int main() {
    // AES-128 example from FIPS-197 Appendix C.1
    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
    std::array<std::uint8_t, 16> plain {};
    for (std::uint8_t i = 0; i < 16; ++ i) {
        // 00 11 22 33 ... ff
        plain[i] = i | (i << 4);
    }

    std::array<std::uint8_t, 16> key = {};
    for (std::uint8_t i = 0; i < 16; ++ i) {
        // 00 01 02 03 ... 0f
        key[i] = i;
    }

    // 69c4e0d86a7b0430d8cdb78070b4c55a
    constexpr std::array<std::uint8_t, 16> cipher = {
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    };

    WordArray<4> main_key{};
    main_key.as_array<std::uint8_t>() = key;

    RoundKeys<10> round_keys{};
    round_keys.expand_from(main_key.words);

    StateMatrix state{};
    state.as_array<std::uint8_t>() = plain;

    auto& origin = state;
    auto& keys = round_keys.states;
    constexpr auto round_count = 10;

    const auto printer = print_word_matrix;

    std::print("[round0input] ");
    printer(origin.words);

    std::print("[round0r_key] ");
    printer(keys[0].words);

    origin.add_round_key(keys[0]);
    std::print("[round0start] ");
    printer(origin.words);

    for (std::uint8_t round = 1; round < round_count; ++round) {
        origin.substitute_with(SBox);
        std::print("[round{}s box] ", round);
        printer(origin.words);

        origin.shift_rows();
        std::print("[round{}s row] ", round);
        printer(origin.words);

        origin.mix_columns(CMDSMatrix);
        std::print("[round{}m col] ", round);
        printer(origin.words);

        std::print("[round{}r_key] ", round);
        printer(keys[round].words);

        origin.add_round_key(keys[round]);
        std::print("[round{}a key] ", round);
        printer(origin.words);
    }
    origin.substitute_with(SBox);
    origin.shift_rows();
    origin.add_round_key(keys[round_count]);

    std::print("密文：");
    printer(state.words);

    std::array<std::uint8_t, 16> encrypted {};
    encrypted = state.as_array<std::uint8_t>();
    if (encrypted != cipher) {
        std::println("密文与预期不符");
    }

    round_keys.decrypt(state);
    std::print("明文：");
    printer(state.words);
    std::array<std::uint8_t, 16> decrypted {};
    decrypted = state.as_array<std::uint8_t>();
    if (decrypted != plain) {
        std::println("解密失败：解密后明文与预期不符");
    }
    else {
        std::println("解密成功");
    }
}