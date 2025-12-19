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

using namespace utils;

namespace {

// ========== 全局变量：存储默认进程信息（功能4设置） ==========
std::string g_default_process = "";
int g_default_pid = -1;

// ========== 通用输入函数（补充支持默认值的字符串输入） ==========
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

// 支持默认值的字符串输入函数（用于文件路径、进程名等）
std::string readStringWithDefault(const std::string& prompt, const std::string& def) {
    std::string input;
    std::cout << prompt << "（默认: " << def << "，回车使用默认）：";
    std::getline(std::cin, input);
    return input.empty() ? def : input;
}

// ========== 简化版：从二进制文件读取单条指针链 ==========
bool read_chain_from_bin(FILE* fp, std::vector<size_t>& offsets) {
    offsets.clear();
    size_t offset_count = 0;
    if (fread(&offset_count, sizeof(size_t), 1, fp) != 1) return false;
    if (offset_count == 0 || offset_count > 50) {
        fseek(fp, static_cast<long>(offset_count * sizeof(size_t)), SEEK_CUR);
        return false;
    }
    try {
        offsets.resize(offset_count);
        if (fread(offsets.data(), sizeof(size_t), offset_count, fp) != offset_count) {
            offsets.clear();
            return false;
        }
    } catch (...) {
        offsets.clear();
        return false;
    }
    return true;
}

// ========== 简化版：输出原始指针链 ==========
std::string format_raw_chain(const std::vector<size_t>& offsets) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    uint64_t curr_addr = 0;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i == 0) {
            oss << "0x" << offsets[i];
            curr_addr = offsets[i];
        } else {
            oss << " -> 0x" << offsets[i];
            curr_addr += offsets[i];
        }
    }
    oss << " | 累加地址: 0x" << curr_addr;
    oss << std::nouppercase << std::dec;
    return oss.str();
}

// ========== 功能1：单地址指针扫描 ==========
void single_address_scan(int pid) {
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

    uint32_t max_depth = readInt<uint32_t>("请输入最大搜索深度（默认6）：", 6);
    uint32_t max_offset = readInt<uint32_t>("请输入最大偏移量（默认1024）：", 1024);
    std::string output_file = "pointer_chains.txt";
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

// ========== 功能2：双地址指针链查找 ==========
void dual_address_scan(int pid) {
    std::cout << "\n===== 双地址指针链查找模式 =====\n";
    uint64_t addr1 = 0, addr2 = 0;
    std::string addr_input;

    std::cout << "请输入起始地址（十六进制，不带0x）：";
    std::getline(std::cin, addr_input);
    try { addr1 = std::stoull(addr_input, nullptr, 16); }
    catch (...) { std::cerr << "地址无效，查找取消\n"; return; }

    std::cout << "请输入目标地址（十六进制，不带0x）：";
    std::getline(std::cin, addr_input);
    try { addr2 = std::stoull(addr_input, nullptr, 16); }
    catch (...) { std::cerr << "地址无效，查找取消\n"; return; }

    uint32_t max_depth = readInt<uint32_t>("请输入最大搜索深度（默认6）：", 6);
    uint32_t max_offset = readInt<uint32_t>("请输入最大偏移量（默认1024）：", 1024);
    std::string output_file = "dual_chains.txt";
    std::cout << "输出文件：" << output_file << "\n";

    memtool::base::target_pid = pid;
    chainer::cscan<size_t> scanner;
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_bss + memtool::C_data);

    auto start = std::chrono::high_resolution_clock::now();
    size_t ptr_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    printf("发现潜在指针: %ld | 扫描耗时: %lld ms\n", ptr_count, duration.count());

    std::vector<size_t> target_addrs = {addr1};
    FILE* temp_bin = fopen("temp_chain.bin", "wb+");
    if (!temp_bin) { std::cerr << "错误：无法创建临时文件\n"; return; }
    size_t total_chain = scanner.scan_pointer_chain(target_addrs, max_depth, max_offset, false, 0, temp_bin);
    fclose(temp_bin);
    if (total_chain == 0) { std::cerr << "警告：未扫描到指针链\n"; remove("temp_chain.bin"); return; }

    FILE* temp_bin_read = fopen("temp_chain.bin", "rb+");
    chainer::cformat<size_t> formatter;
    formatter.format_bin_chain_data(temp_bin_read, "temp_chains.txt", false);
    fclose(temp_bin_read);
    remove("temp_chain.bin");

    FILE* temp_txt = fopen("temp_chains.txt", "r");
    FILE* fp = fopen(output_file.c_str(), "w+");
    if (!temp_txt || !fp) { std::cerr << "错误：文件打开失败\n"; return; }

    size_t valid_count = 0;
    char line_buf[2048];
    while (fgets(line_buf, sizeof(line_buf), temp_txt)) {
        std::string line(line_buf);
        std::vector<size_t> offsets;
        size_t pos = 0;
        while ((pos = line.find("0x", pos)) != std::string::npos) {
            pos += 2;
            size_t end = line.find_first_of(" ->= \n\r", pos);
            if (end == std::string::npos) break;
            try { offsets.push_back(std::stoull(line.substr(pos, end - pos), nullptr, 16)); }
            catch (...) { break; }
            pos = end;
        }
        if (!offsets.empty()) {
            uint64_t curr = 0;
            for (size_t off : offsets) curr += off;
            if (curr == addr2) {
                valid_count++;
                fprintf(fp, "%s\n", line.c_str());
                printf("有效链: %s\n", line.c_str());
            }
        }
    }

    fclose(temp_txt);
    fclose(fp);
    remove("temp_chains.txt");
    printf("查找完成！有效链总数: %ld | 结果已保存至: %s\n", valid_count, output_file.c_str());
}

// ========== 功能3：解析二进制文件（支持手动输入路径+默认值） ==========
void parse_binary_file() {
    const std::string DEFAULT_BIN = "temp_chain.bin";
    const std::string OUTPUT_FILE = "parsed_100_chains.txt";
    const size_t MAX_OUTPUT = 100;

    std::cout << "\n===== 解析二进制文件 =====\n";
    // 支持手动输入文件路径，回车使用默认
    std::string bin_file = readStringWithDefault("请输入二进制文件路径", DEFAULT_BIN);

    // 检查文件是否存在
    FILE* bin_fp = fopen(bin_file.c_str(), "rb");
    if (!bin_fp) {
        std::cerr << "错误：未找到文件 " << bin_file << "！\n";
        return;
    }

    // 打开输出文件
    FILE* out_fp = fopen(OUTPUT_FILE.c_str(), "w+");
    if (!out_fp) {
        std::cerr << "错误：无法创建输出文件 " << OUTPUT_FILE << "\n";
        fclose(bin_fp);
        return;
    }

    std::vector<size_t> offsets;
    size_t output_count = 0;
    size_t skip_count = 0;

    std::cout << "\n正在解析 " << bin_file << "，自动输出前" << MAX_OUTPUT << "条有效链...\n";
    while (output_count < MAX_OUTPUT) {
        if (!read_chain_from_bin(bin_fp, offsets)) break;
        if (offsets.empty()) {
            skip_count++;
            continue;
        }
        std::string chain_line = format_raw_chain(offsets);
        fprintf(out_fp, "第%ld条: %s\n", output_count + 1, chain_line.c_str());
        printf("第%ld条: %s\n", output_count + 1, chain_line.c_str());
        output_count++;
        offsets.clear();
    }

    fclose(bin_fp);
    fclose(out_fp);

    std::cout << "\n解析完成！\n";
    std::cout << "成功输出: " << output_count << " 条（最多" << MAX_OUTPUT << "条）\n";
    std::cout << "跳过无效链: " << skip_count << " 条\n";
    std::cout << "结果已保存至: " << OUTPUT_FILE << "\n";
}

// ========== 新增功能4：设置默认包名/进程名 ==========
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
    } else {
        std::cerr << "错误：无法找到进程 " << process << "，设置失败\n";
    }
}

}  // namespace

// ========== 主函数（菜单调整+默认进程逻辑） ==========
int main() {
    std::cout << "===== 内存指针链分析工具（增强版）=====\n";

    // 检查默认进程是否已设置
    int pid = -1;
    if (g_default_pid != -1) {
        pid = g_default_pid;
        printf("已加载默认进程: %s | PID: %d\n", g_default_process.c_str(), pid);
    } else {
        // 未设置默认进程，提示用户输入（可选）
        std::string process = readStringWithDefault("请输入目标进程名或PID（仅扫描/查找功能需要，可后续通过功能4设置默认）", "");
        if (!process.empty()) {
            try {
                pid = std::stoi(process);
            } catch (...) {
                pid = memtool::base::get_pid(process.c_str());
            }
            if (pid != -1) {
                printf("成功附加进程: %s | PID: %d\n", process.c_str(), pid);
            } else {
                std::cerr << "警告：进程未找到，仅解析功能可用\n";
            }
        } else {
            std::cerr << "未输入进程信息，仅解析功能可用\n";
        }
    }

    // 菜单循环（新增功能4，退出改为5）
    int choice = 0;
    while (true) {
        std::cout << "\n===== 功能菜单 =====\n";
        std::cout << "1. 单地址指针扫描\n";
        std::cout << "2. 双地址指针链查找\n";
        std::cout << "3. 解析二进制文件（支持默认路径）\n";
        std::cout << "4. 设置默认包名/进程名\n";
        std::cout << "5. 退出程序\n";
        choice = readInt<int>("请输入功能选项 [1-5]（默认5）：", 5);

        switch (choice) {
            case 1:
                if (pid != -1) {
                    single_address_scan(pid);
                } else {
                    std::cerr << "错误：无有效进程，无法扫描\n";
                }
                break;
            case 2:
                if (pid != -1) {
                    dual_address_scan(pid);
                } else {
                    std::cerr << "错误：无有效进程，无法查找\n";
                }
                break;
            case 3:
                parse_binary_file();
                break;
            case 4:
                set_default_process();
                // 设置后更新当前pid
                pid = g_default_pid;
                break;
            case 5:
                std::cout << "程序退出中...\n";
                return 0;
            default:
                std::cerr << "无效选项，自动退出\n";
                return 0;
        }
    }

    return 0;
}
