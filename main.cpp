#include "memtool/membase.hpp"
#include "memtool/memextend.hpp"
#include "chainer/ccscan.hpp"
#include "chainer/ccompare.hpp"
#include "chainer/ccformat.hpp"
#include "utils/cmd_parser.h"
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <limits>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <endian.h>

using namespace utils;

namespace {

// 全局常量（适配仓库输出路径）
const std::string OUTPUT_DIR = "/sdcard/CK_PointerTool/";
const std::string DEFAULT_PROCESS_FILE = OUTPUT_DIR + "default_process.txt";

// 全局变量：持久化默认进程
std::string g_default_process = "";
int g_default_pid = -1;

// ========== 工具函数：创建文件夹（兼容仓库运行环境） ==========
bool create_output_dir() {
    std::string cmd = "mkdir -p " + OUTPUT_DIR;
    int ret = system(cmd.c_str());
    return ret != -1;
}

// ========== 工具函数：拼接路径 ==========
std::string get_full_path(const std::string& filename) {
    return OUTPUT_DIR + filename;
}

// ========== 持久化：保存默认进程到文件 ==========
bool save_default_process_to_file() {
    if (g_default_process.empty() || g_default_pid == -1) return false;
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "w");
    if (!fp) return false;
    fprintf(fp, "%s\n%d", g_default_process.c_str(), g_default_pid);
    fclose(fp);
    return true;
}

// ========== 持久化：加载默认进程 ==========
bool load_default_process_from_file() {
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "r");
    if (!fp) return false;

    char process_buf[256] = {0};
    char pid_buf[32] = {0};
    if (fgets(process_buf, sizeof(process_buf), fp) == nullptr ||
        fgets(pid_buf, sizeof(pid_buf), fp) == nullptr) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    g_default_process = std::string(process_buf).erase(std::string(process_buf).find_last_not_of("\n\r") + 1);
    try {
        g_default_pid = std::stoi(std::string(pid_buf).erase(std::string(pid_buf).find_last_not_of("\n\r") + 1));
    } catch (...) {
        g_default_process.clear();
        g_default_pid = -1;
        return false;
    }

    return memtool::base::get_pid(g_default_process.c_str()) != -1;
}

// ========== 通用输入函数（适配仓库参数类型） ==========
template <typename T>
typename std::enable_if<std::is_integral<T>::value, T>::type
readInt(const std::string& prompt, T def = T()) {
    std::string input;
    std::cout << prompt;
    std::getline(std::cin, input);
    if (input.empty()) return def;
    try {
        uint64_t val = std::stoull(input);
        if (val > std::numeric_limits<T>::max()) throw std::out_of_range("");
        return static_cast<T>(val);
    } catch (...) {
        return def;
    }
}

std::string readStringWithDefault(const std::string& prompt, const std::string& def) {
    std::string input;
    std::cout << prompt << "（默认: " << def << "，回车使用默认）：";
    std::getline(std::cin, input);
    return input.empty() ? def : input;
}

// ========== 指针链格式化（保持GG修改器适配格式） ==========
std::string format_raw_chain(const std::vector<size_t>& offsets) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i == 0) {
            oss << "0x" << offsets[i];
        } else {
            oss << " -> +0x" << offsets[i];
        }
    }
    oss << std::nouppercase << std::dec;
    return oss.str();
}

// ========== 功能1：单地址扫描（保持原参数设置） ==========
void single_address_scan(int pid) {
    if (!create_output_dir()) return;

    std::cout << "\n===== 单地址指针扫描模式 =====\n";
    uint64_t target_addr = 0;
    std::string addr_input;
    std::cout << "请输入目标地址（十六进制，不带0x）：";
    std::getline(std::cin, addr_input);
    try {
        target_addr = std::stoull(addr_input, nullptr, 16);
    } catch (...) {
        std::cerr << "地址无效，扫描取消\n";
        return;
    }

    // 保持原默认值和输入逻辑，不修改深度/偏移限制
    uint32_t max_depth = readInt<uint32_t>("请输入最大搜索深度（默认6）：", 6);
    uint32_t max_offset = readInt<uint32_t>("请输入最大偏移量（默认1024）：", 1024);
    std::string output_file = get_full_path("pointer_chains.txt");
    std::cout << "输出文件：" << output_file << "\n";

    memtool::base::target_pid = pid;
    chainer::cscan<size_t> scanner;
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_bss + memtool::C_data);

    auto start = std::chrono::high_resolution_clock::now();
    size_t ptr_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    printf("发现潜在指针: %ld | 扫描耗时: %lld ms\n", ptr_count, duration.count());

    std::vector<size_t> target_addrs = {target_addr};
    FILE* fp = fopen(output_file.c_str(), "w+");
    if (!fp) {
        std::cerr << "错误：无法创建文件 " << output_file << "\n";
        return;
    }

    size_t chain_count = scanner.scan_pointer_chain_to_txt(target_addrs, max_depth, max_offset, false, 0, fp);
    fclose(fp);
    printf("扫描完成！找到指针链总数: %ld | 结果已保存至: %s\n", chain_count, output_file.c_str());
}

// ========== 功能2：双地址查找（同时生成二进制+文本文件） ==========
void dual_address_scan(int pid) {
    if (!create_output_dir()) return;

    std::cout << "\n===== 双地址指针链查找（生成二进制+文本文件）=====\n";
    std::cout << "文件保存至：" << OUTPUT_DIR << "\n";

    uint64_t addr1 = 0, addr2 = 0;
    std::string addr_input;

    std::cout << "请输入起始地址（十六进制，不带0x）：";
    std::getline(std::cin, addr_input);
    try {
        addr1 = std::stoull(addr_input, nullptr, 16);
    } catch (...) {
        std::cerr << "地址无效，查找取消\n";
        return;
    }

    std::cout << "请输入目标地址（十六进制，不带0x）：";
    std::getline(std::cin, addr_input);
    try {
        addr2 = std::stoull(addr_input, nullptr, 16);
    } catch (...) {
        std::cerr << "地址无效，查找取消\n";
        return;
    }

    // 保持原默认值和输入逻辑，不强制修改深度/偏移
    uint32_t max_depth = readInt<uint32_t>("请输入最大搜索深度（默认6）：", 6);
    uint32_t max_offset = readInt<uint32_t>("请输入最大偏移量（默认1024）：", 1024);
    uint32_t chain_limit = readInt<uint32_t>("请输入生成指针链上限（默认100000）：", 100000);

    memtool::base::target_pid = pid;
    chainer::cscan<size_t> scanner;
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_bss + memtool::C_data);

    auto start_total = std::chrono::high_resolution_clock::now();
    auto start_scan = std::chrono::high_resolution_clock::now();
    size_t ptr_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
    auto duration_scan = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_scan);
    printf("\n发现潜在指针: %ld | 扫描耗时: %lld ms\n", ptr_count, duration_scan.count());

    std::vector<size_t> target_addrs = {addr1, addr2};
    
    // 1. 生成二进制文件（保持原有逻辑）
    std::string temp_bin_path = get_full_path("temp_chain.bin");
    FILE* temp_bin = fopen(temp_bin_path.c_str(), "wb+");
    if (!temp_bin) { 
        std::cerr << "错误：无法创建二进制文件 " << temp_bin_path << "\n"; 
        return; 
    }

    // 2. 生成文本文件（新增：格式适配GG修改器）
    std::string txt_path = get_full_path("pointer_chains_dual.txt");
    FILE* txt_file = fopen(txt_path.c_str(), "w+");
    if (!txt_file) {
        std::cerr << "错误：无法创建文本文件 " << txt_path << "\n";
        fclose(temp_bin);
        return;
    }

    auto start_gen = std::chrono::high_resolution_clock::now();
    // 生成二进制文件
    size_t total_chain = scanner.scan_pointer_chain(target_addrs, max_depth, max_offset, false, chain_limit, temp_bin);
    // 同时生成文本文件（调用生成文本的接口，复用格式逻辑）
    scanner.scan_pointer_chain_to_txt(target_addrs, max_depth, max_offset, false, 0, txt_file);
    
    // 关闭文件
    fclose(temp_bin);
    fclose(txt_file);
    
    auto duration_gen = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_gen);
    auto duration_total = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_total);

    std::cout << "\n===== 生成完成 =====\n";
    std::cout << "生成指针链总数: " << total_chain << " 条\n";
    std::cout << "二进制文件：" << temp_bin_path << "\n";
    std::cout << "文本文件：" << txt_path << "\n";
    std::cout << "生成耗时: " << duration_gen.count() << " ms\n";
    std::cout << "总耗时: " << duration_total.count() << " ms\n";
}

// ========== 功能3：设置默认进程（持久化） ==========
void set_default_process() {
    std::cout << "\n===== 设置默认包名/进程名 =====\n";
    std::string process = readStringWithDefault("请输入默认进程名或PID", g_default_process.empty() ? "无" : g_default_process);
    if (process == "无") {
        std::cerr << "未输入进程信息，设置取消\n";
        return;
    }

    int pid = -1;
    try {
        pid = std::stoi(process);
    } catch (...) {
        pid = memtool::base::get_pid(process.c_str());
    }

    if (pid != -1) {
        g_default_process = process;
        g_default_pid = pid;
        printf("设置成功！默认进程: %s | PID: %d\n", process.c_str(), pid);
        if (save_default_process_to_file()) {
            std::cout << "默认进程已保存，下次启动自动加载\n";
        }
    } else {
        std::cerr << "错误：无法找到进程 " << process << "，设置失败\n";
    }
}

}  // namespace

// ========== 主函数（彻底移除功能3相关逻辑） ==========
int main() {
    std::cout << "===== 内存指针链分析工具（仓库适配最终版）=====\n";
    std::cout << "适配仓库：https://github.com/sycmi/6666.git\n";
    std::cout << "所有文件保存至：" << OUTPUT_DIR << "\n";

    if (!create_output_dir()) {
        std::cerr << "程序启动失败：无法创建输出文件夹\n";
        return 1;
    }

    if (load_default_process_from_file()) {
        std::cout << "已加载默认进程：" << g_default_process << " | PID: " << g_default_pid << "\n";
    } else {
        std::cout << "未找到保存的默认进程\n";
    }

    int pid = -1;
    std::string prompt = "请输入目标进程名或PID（";
    prompt += g_default_process.empty() ? "无默认，留空仅扫描/查找功能可用" : "回车使用默认[" + g_default_process + "]";
    prompt += "）：";

    std::string process_input;
    std::cout << prompt;
    std::getline(std::cin, process_input);

    if (!process_input.empty()) {
        try {
            pid = std::stoi(process_input);
        } catch (...) {
            pid = memtool::base::get_pid(process_input.c_str());
        }
        if (pid != -1) {
            g_default_process = process_input;
            g_default_pid = pid;
            printf("成功附加新进程: %s | PID: %d\n", process_input.c_str(), pid);
            save_default_process_to_file();
        } else {
            std::cerr << "警告：输入的进程未找到，仅扫描/查找功能可用\n";
        }
    } else {
        pid = g_default_pid;
        if (pid != -1) {
            std::cout << "已使用默认进程: " << g_default_process << " | PID: " << g_default_pid << "\n";
        } else {
            std::cerr << "未输入进程信息，仅扫描/查找功能可用\n";
        }
    }

    int choice = 0;
    while (true) {
        std::cout << "\n===== 功能菜单 =====\n";
        std::cout << "1. 单地址指针扫描（生成文本文件）\n";
        std::cout << "2. 双地址指针链查找（生成二进制+文本文件）\n";
        std::cout << "3. 修改默认包名/进程名\n";
        std::cout << "4. 退出程序\n";
        choice = readInt<int>("请输入功能选项 [1-4]（默认4）：", 4);

        switch (choice) {
            case 1:
                if (pid != -1) single_address_scan(pid);
                else std::cerr << "错误：无有效进程，无法扫描\n";
                break;
            case 2:
                if (pid != -1) dual_address_scan(pid);
                else std::cerr << "错误：无有效进程，无法查找\n";
                break;
            case 3:
                set_default_process();
                pid = g_default_pid; // 更新pid，避免重新输入
                break;
            case 4:
                std::cout << "程序退出中...\n";
                return 0;
            default:
                std::cerr << "无效选项，自动退出\n";
                return 0;
        }
    }

    return 0;
}
