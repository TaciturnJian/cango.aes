#include <string>

#include "toolbox.hpp"

using namespace cango::aes::details;

void test_xtime(toolbox& tb) {
    const std::vector<std::pair<std::uint8_t, std::uint8_t>> cases{
            {0x57, 0xAE}, // 规范示例: xtime(0x57) == 0xAE
            {0x83, 0x1D}, // xtime(0x83) == 0x1D
            {0x00, 0x00}, // 边界: 0 -> 0
        };
    for (const auto &p : cases) {
        const auto name = std::format("xtime({})", p.first);
        tb.execute(name, [p] {
            return xtime(p.first) == p.second;
        });
    }
}

void test_gf_mul(toolbox& tb) {
    const std::vector<std::tuple<std::uint8_t, std::uint8_t, std::uint8_t>> cases{
            {0x57, 0x13, 0xFE}, // 规范示例: 0x57 * 0x13 == 0xFE
            {0x57, 0x02, 0xAE}, // 0x57 * 0x02 == xtime(0x57) == 0xAE
            {0x57, 0x03, 0xF9}, // 0x57 * 0x03 == xtime(0x57) ^ 0x57 == 0xF9
            {0x00, 0xFF, 0x00}, // 0 * anything == 0
            {0xFF, 0x00, 0x00}  // anything * 0 == 0
    };
    for (const auto &p : cases) {
        const auto name = std::format("gf_mul({}, {})", std::get<0>(p), std::get<1>(p));
        tb.execute(name, [p] {
            return gf_mul(std::get<0>(p), std::get<1>(p)) == std::get<2>(p);
        });
    }
}

int main() {
    toolbox tb{true};
    test_xtime(tb);
    test_gf_mul(tb);
    tb.summary();
}
