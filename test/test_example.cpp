#include <random>

#include "toolbox.hpp"

void generate_int(auto& numbers) {
    auto& ints = reinterpret_cast<std::array<int, sizeof(numbers) / sizeof(int)>&>(numbers);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis{};
    for (auto& i : ints) {
        i = dis(gen);
    }
}

void print_bytes(const auto& bytes) {
    for (const auto byte : bytes) {
        std::cout << std::format("{:02X}", byte);
    }
}

int main() {
    using namespace cango::aes;

    std::array<std::uint8_t, 16> main_key{};
    generate_int(main_key);
    std::cout << "主密钥:\t\t";
    print_bytes(main_key);
    std::cout << std::endl;


    const AES128Cryptor cryptor{main_key};

    std::array<std::uint8_t, 16> plain {
        'h', 'e', 'l', 'l',
        'o', 'W', 'o', 'r',
        'l', 'd', '!',
    };
    std::cout << "plain:\t\t";
    print_bytes(plain);
    std::cout << std::endl;

    auto buffer = plain;
    cryptor.encrypt(buffer);
    std::cout << "encrypted:\t";
    print_bytes(buffer);
    std::cout << std::endl;

    cryptor.decrypt(buffer);
    std::cout << "decrypted:\t";
    print_bytes(buffer);
    std::cout << std::endl;

    if (buffer != plain) {
        std::cout << "解密结果与原文不一致！\n";
        return 1;
    }

    std::cout << "解密成功\n";
    return 0;
}