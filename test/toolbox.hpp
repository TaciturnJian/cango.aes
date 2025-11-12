#pragma once

#include <format>
#include <functional>
#include <iostream>
#include <print>

#include <cango/aes.hpp>

using namespace cango::aes;
using namespace cango::aes::details;

inline void print_word(const Word &word) { for (const auto byte: word.bytes) std::print(" {:02x}", byte); }

inline void print_word_matrix(const std::span<const Word> matrix) {
    std::cout << "[";
    for (const auto byte : matrix) {
        print_word(byte);
    }
    std::cout << " ]" << std::dec << std::endl;
}

inline void print_word_matrix_row(const std::span<const Word> matrix) {
    std::cout << "[";
    for (const auto &row: matrix)
        print_word(row);

    std::cout << " ]" << std::dec << std::endl;
}

struct toolbox {
    bool verbose;

    std::list<std::pair<std::string, bool> > records;
    std::size_t failed;
    std::size_t passed;

    template<typename... Args>
    void log(const std::format_string<Args...> fmt, Args &&... args) {
        if (!verbose) return;
        std::println(fmt, std::forward<Args>(args)...);
    }

    void execute(const std::string_view name, const std::function<bool()> &func) {
        try {
            log("[test] 正在测试：{}", name);
            if (func()) {
                log("[test] 测试通过：{}", name);
                ++passed;
            }
            else {
                log("[test] 测试失败：{}", name);
                ++failed;
            }
        }
        catch (const std::exception &e) {
            log("[test] 测试({})出现异常，异常信息：{}", name, e.what());
            ++failed;
        }
        catch (...) {
            log("[test] 测试({})出现异常", name);
            ++failed;
        }
    }

    void summary() { log("[test] 通过数：{}, 失败数：{}", passed, failed); }
};
