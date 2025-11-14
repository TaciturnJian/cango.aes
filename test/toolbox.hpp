#pragma once

#include <format>
#include <functional>
#include <iostream>
#include <list>
#include <print>
#include <sstream>

#include <cango/aes.hpp>

using namespace cango::aes;
using namespace cango::aes::details;

std::string bytes_to_string(const auto& bytes) {
    std::ostringstream ss{};
    for (const auto byte: bytes) {
        std::print(ss, " {:02x}", byte);
    }
    return ss.str();
}

struct toolbox {
    bool verbose;

    std::list<std::pair<std::string, bool> > records;
    std::size_t failed;
    std::size_t passed;

    template<typename... Args>
    void log(const std::format_string<Args...> fmt, Args &&... args) {
        if (!verbose) return;
        std::cout << std::format(fmt, std::forward<Args>(args)...) << std::endl;
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
