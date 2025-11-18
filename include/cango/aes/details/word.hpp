#ifndef INCLUDE_CANGO_AES_DETAILS_WORD
#define INCLUDE_CANGO_AES_DETAILS_WORD

#include <array>

#include "sbox.hpp"
#include "utils.hpp"

namespace cango::aes::details {

using Word = std::array<std::uint8_t, 4>;

constexpr Word operator^(const Word& lhs, const Word& rhs) noexcept {
    Word result{};
    for (std::size_t i = 0; i < 4; ++i)
        result[i] = lhs[i] ^ rhs[i];
    return result;
}

}

#endif//INCLUDE_CANGO_AES_DETAILS_WORD
