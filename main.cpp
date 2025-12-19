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

using namespace utils;

namespace {

// 全局常量
const std::string OUTPUT_DIR = "/sdcard/CK_PointerTool/";
const std::string DEFAULT_PROCESS_FILE = OUTPUT_DIR + "default_process.txt"; // 保存默认包名的文件

// 全局变量：默认进程信息（持久化）
std::string g_default_process = "";
int g_default_pid = -1;

// ========== 工具函数：创建输出文件夹 ==========
bool create_output_dir() {
    std::string cmd = "mkdir -p " + OUTPUT_DIR;
    int ret = system(cmd.c_str());
    if (ret == -1) {
        std::cerr << "错误：创建文件夹失败 -> " << OUTPUT_DIR << "\n";
        return false;
    }
    return true;
}

// ========== 工具函数：拼接文件路径 ==========
std::string get_full_path(const std::string& filename) {
    return OUTPUT_DIR + filename;
}

// ========== 新增：持久化工具函数（保存默认进程到文件） ==========
bool save_default_process_to_file() {
    if (g_default_process.empty() || g_default_pid == -1) {
        std::cerr << "警告：无有效默认进程可保存\n";
        return false;
    }
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "w");
    if (!fp) {
        std::cerr << "错误：无法保存默认进程到文件 -> " << DEFAULT_PROCESS_FILE << "\n";
        return false;
    }
    // 格式：进程名/PID\nPID（避免重复解析）
    fprintf(fp, "%s\n%d", g_default_process.c_str(), g_default_pid);
    fclose(fp);
    return true;
}

// ========== 新增：持久化工具函数（从文件读取默认进程） ==========
bool load_default_process_from_file() {
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "r");
    if (!fp) {
        // 文件不存在=无默认进程，不报错
        return false;
    }
    char process_buf[256] = {0};
    char pid_buf[32] = {0};
    // 读取第一行：进程名/PID，第二行：PID
    if (fgets(process_buf, sizeof(process_buf), fp) == nullptr ||
        fgets(pid_buf, sizeof(pid_buf), fp) == nullptr) {
        fclose(fp);
        std::cerr << "警告：默认进程文件格式错误\n";
        return false;
    }
    fclose(fp);
    // 去除换行符
    g_default_process = std::string(process_buf).erase(std::string(process_buf).find_last_not_of("\n\r") + 1);
    try {
        g_default_pid = std::stoi(std::string(pid_buf).erase(std::string(pid_buf).find_last_not_of("\n\r") + 1));
    } catch (...) {
        std::cerr << "警告：默认进程PID解析失败\n";
        g_default_process.clear();
        g_default_pid = -1;
        return false;
    }
    // 验证PID有效性（可选，避免保存的PID已失效）
    if (memtool::base::get_pid(g_default_process.c_str()) == -1) {
        std::cerr << "警告：保存的默认进程已不存在\n";
        g_default_process.clear();
        g_default_pid = -1;
        return false;
    }
    return true;
}

// ========== 通用输入函数 ==========
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

// ========== 工具函数：获取文件大小 ==========
long get_file_size(const std::string& file_path) {
    struct stat file_stat;
    return (stat(file_path.c_str(), &file_stat) == 0) ? file_stat.st_size : -1;
}

// ========== 核心解析函数 ==========
bool read_chain_from_bin(FILE* fp, std::vector<size_t>& offsets, size_t& debug_chain_len, size_t& debug_target_addr, std::string& debug_error) {
    offsets.clear();
    debug_chain_len = 0;
    debug_target_addr = 0;
    debug_error = "";

    uint32_t chain_len = 0;
    long curr_pos = ftell(fp);

    if (fread(&chain_len, sizeof(uint32_t), 1, fp) != 1) {
        debug_error = "读取链长度失败";
        return false;
    }
    debug_chain_len = static_cast<size_t>(chain_len);

    if (chain_len == 0 || chain_len > 20) {
        long skip_bytes = static_cast<long>(chain_len * sizeof(size_t) + sizeof(size_t));
        fseek(fp, skip_bytes, SEEK_CUR);
        debug_error = "链长度无效（" + std::to_string(chain_len) + "）";
        return false;
    }

    offsets.resize(chain_len);
    if (fread(offsets.data(), sizeof(size_t), chain_len, fp) != chain_len) {
        long skip_bytes = static_cast<long>(chain_len * sizeof(size_t) + sizeof(size_t));
        fseek(fp, skip_bytes - static_cast<long>(offsets.size() * sizeof(size_t)), SEEK_CUR);
        offsets.clear();
        debug_error = "偏移数组读取不完整";
        return false;
    }

    if (fread(&debug_target_addr, sizeof(size_t), 1, fp) != 1) {
        offsets.clear();
        debug_error = "读取目标地址失败";
        return false;
    }

    if (offsets.empty()) {
        debug_error = "偏移数组为空";
        return false;
    }

    return true;
}

// ========== 指针链格式化输出 ==========
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

// ========== 功能2：双地址指针链查找 ==========
void dual_address_scan(int pid) {
    if (!create_output_dir()) return;

    std::cout << "\n===== 双地址指针链查找（仅生成二进制）=====\n";
    std::cout << "说明：文件保存至 " << OUTPUT_DIR << "\n";

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
    std::string temp_bin_path = get_full_path("temp_chain.bin");
    FILE* temp_bin = fopen(temp_bin_path.c_str(), "wb+");
    if (!temp_bin) { 
        std::cerr << "错误：无法创建二进制文件 " << temp_bin_path << "\n"; 
        return; 
    }

    auto start_gen = std::chrono::high_resolution_clock::now();
    size_t total_chain = scanner.scan_pointer_chain(target_addrs, max_depth, max_offset, false, chain_limit, temp_bin);
    fclose(temp_bin);
    auto duration_gen = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_gen);

    auto duration_total = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start_total);
    std::cout << "\n===== 生成完成 =====\n";
    std::cout << "生成指针链总数: " << total_chain << " 条\n";
    std::cout << "生成耗时: " << duration_gen.count() << " ms\n";
    std::cout << "总耗时: " << duration_total.count() << " ms\n";
    std::cout << "二进制文件：" << temp_bin_path << "\n";
}

// ========== 功能3：解析二进制文件 ==========
void parse_binary_file() {
    if (!create_output_dir()) return;

    const std::string DEFAULT_BIN = get_full_path("temp_chain.bin");
    const std::string OUTPUT_FILE = get_full_path("parsed_100_chains.txt");
    const size_t MAX_OUTPUT = 100;

    std::cout << "\n===== 解析二进制文件（增强容错+调试模式）=====\n";
    std::cout << "默认读取文件：" << DEFAULT_BIN << "\n";
    std::string bin_file = readStringWithDefault("请输入二进制文件路径", DEFAULT_BIN);

    long file_size = get_file_size(bin_file);
    if (file_size < 0) {
        std::cerr << "错误：文件不存在或无法访问 -> " << bin_file << "\n";
        return;
    }
    if (file_size == 0) {
        std::cerr << "错误：文件为空 -> " << bin_file << "\n";
        return;
    }
    std::cout << "文件信息：路径=" << bin_file << " | 大小=" << file_size << "字节\n";
    std::cout << "预计链数量：" << (file_size / (4 + 8 + 8)) << " 条\n";

    FILE* bin_fp = fopen(bin_file.c_str(), "rb");
    if (!bin_fp) {
        std::cerr << "错误：无法打开文件 -> " << bin_file << "\n";
        return;
    }

    FILE* out_fp = fopen(OUTPUT_FILE.c_str(), "w+");
    if (!out_fp) {
        std::cerr << "错误：无法创建输出文件 -> " << OUTPUT_FILE << "\n";
        fclose(bin_fp);
        return;
    }

    std::vector<size_t> offsets;
    size_t output_count = 0;
    size_t skip_count = 0;
    size_t total_parse_attempt = 0;
    size_t debug_chain_len = 0;
    size_t debug_target_addr = 0;
    std::string debug_error = "";

    std::cout << "\n开始解析（前" << MAX_OUTPUT << "条）...\n";
    std::cout << "===========================================\n";
    while (output_count < MAX_OUTPUT) {
        total_parse_attempt++;
        bool parse_ok = read_chain_from_bin(bin_fp, offsets, debug_chain_len, debug_target_addr, debug_error);

        if (total_parse_attempt % 10 == 0 || !parse_ok) {
            std::cout << "尝试解析第" << total_parse_attempt << "条：";
            if (parse_ok) {
                std::cout << "成功（链长度=" << debug_chain_len << "，目标地址=0x" << std::hex << debug_target_addr << std::dec << "）\n";
            } else {
                std::cout << "失败（" << debug_error << "）\n";
            }
        }

        if (!parse_ok) {
            skip_count++;
            if (feof(bin_fp)) {
                std::cout << "\n文件解析完毕\n";
                break;
            }
            continue;
        }

        if (offsets.empty()) {
            skip_count++;
            continue;
        }

        std::string chain_line = format_raw_chain(offsets);
        fprintf(out_fp, "第%ld条: %s | 目标地址: 0x%lx\n", output_count + 1, chain_line.c_str(), debug_target_addr);
        printf("第%ld条: %s | 目标地址: 0x%lx\n", output_count + 1, chain_line.c_str(), debug_target_addr);
        output_count++;
        offsets.clear();
    }
    std::cout << "===========================================\n";

    fclose(bin_fp);
    fclose(out_fp);

    std::cout << "\n===== 解析统计 =====\n";
    std::cout << "成功输出: " << output_count << " 条 | 跳过无效链: " << skip_count << " 条\n";
    std::cout << "结果已保存至: " << OUTPUT_FILE << "\n";
}

// ========== 功能4：设置默认包名/进程名（修改：设置后自动保存到文件） ==========
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
        // 保存到文件，持久化
        if (save_default_process_to_file()) {
            std::cout << "默认进程已保存，下次启动自动加载\n";
        }
    } else {
        std::cerr << "错误：无法找到进程 " << process << "，设置失败\n";
    }
}

}  // namespace

// ========== 主函数（核心修改：修复三元运算符为if-else） ==========
int main() {
    std::cout << "===== 内存指针链分析工具（持久化默认进程版）=====\n";
    std::cout << "适配仓库：https://github.com/sycmi/6666.git\n";
    std::cout << "所有文件保存至：" << OUTPUT_DIR << "\n";

    // 1. 提前创建输出文件夹
    if (!create_output_dir()) {
        std::cerr << "程序启动失败：无法创建输出文件夹\n";
        return 1;
    }

    // 2. 自动加载保存的默认进程（从文件读取）
    if (load_default_process_from_file()) {
        std::cout << "已加载默认进程：" << g_default_process << " | PID: " << g_default_pid << "\n";
    } else {
        std::cout << "未找到保存的默认进程\n";
    }

    // 3. 询问用户是否输入新进程（回车=使用默认，无默认则留空）
    int pid = -1;
    std::string prompt = "请输入目标进程名或PID（";
    if (!g_default_process.empty()) {
        prompt += "回车使用默认[" + g_default_process + "]";
    } else {
        prompt += "无默认，留空则仅解析功能可用";
    }
    prompt += "）：";

    std::string process_input;
    std::cout << prompt;
    std::getline(std::cin, process_input);

    if (!process_input.empty()) {
        // 输入了新进程，解析并更新默认
        try {
            pid = std::stoi(process_input);
        } catch (...) {
            pid = memtool::base::get_pid(process_input.c_str());
        }
        if (pid != -1) {
            g_default_process = process_input;
            g_default_pid = pid;
            printf("成功附加新进程: %s | PID: %d\n", process_input.c_str(), pid);
            save_default_process_to_file(); // 保存新进程为默认
        } else {
            std::cerr << "警告：输入的进程未找到，仅解析功能可用\n";
        }
    } else {
        // 未输入（回车），使用加载的默认进程
        pid = g_default_pid;
        if (pid != -1) {
            std::cout << "已使用默认进程: " << g_default_process << " | PID: " << pid << "\n";
        } else {
            std::cerr << "未输入进程信息，仅解析功能可用\n";
        }
    }

    // 4. 菜单循环（修复三元运算符为if-else）
    int choice = 0;
    while (true) {
        std::cout << "\n===== 功能菜单 =====\n";
        std::cout << "1. 单地址指针扫描（生成文本文件）\n";
        std::cout << "2. 双地址指针链查找（仅生成二进制）\n";
        std::cout << "3. 解析二进制文件（增强容错+调试）\n";
        std::cout << "4. 修改默认包名/进程名\n";
        std::cout << "5. 退出程序\n";
        choice = readInt<int>("请输入功能选项 [1-5]（默认5）：", 5);

        switch (choice) {
            case 1:
                // 修复：三元运算符改为if-else
                if (pid != -1) {
                    single_address_scan(pid);
                } else {
                    std::cerr << "错误：无有效进程，无法扫描\n";
                }
                break;
            case 2:
                // 修复：三元运算符改为if-else + 去除错误提示前的多余空格
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
                pid = g_default_pid; // 更新当前PID为新默认
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
