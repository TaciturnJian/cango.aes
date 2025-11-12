#include <span>

#include <cango/aes.hpp>

#include "toolbox.hpp"

using namespace cango::aes;

int main() {
    constexpr std::array<std::uint8_t, 16> cipher{
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    constexpr std::array<std::uint8_t, 4> last_word{
        0xb6, 0x63, 0x0c, 0xa6
    };

    WordArray<4> main_key;
    main_key.as_array<std::uint8_t>() = cipher;

    RoundKeys<10> round_keys{};
    round_keys.expand_from(main_key);

    for (std::uint8_t index = 0; index < 44; ++index) {
        std::print("[index{:2}] ", index);
        print_word(round_keys.at_word(index));
        std::cout << std::endl;
    }

    if (round_keys.at_word(43).bytes != last_word) {
        std::println("轮钥与预期不符");
        return 1;
    }
    return 0;
}