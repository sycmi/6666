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
#include <dirent.h>
#include <regex>
#include <algorithm>
#include <set>

using namespace utils;

namespace {

// 全局常量（适配仓库输出路径）
const std::string OUTPUT_DIR = "/sdcard/CK_PointerTool/";
const std::string DEFAULT_PROCESS_FILE = OUTPUT_DIR + "default_process.txt";

// 全局变量：仅保存默认包名
std::string g_default_process = "";

// ========== 工具函数：创建文件夹 ==========
bool create_output_dir() {
    std::string cmd = "mkdir -p " + OUTPUT_DIR;
    int ret = system(cmd.c_str());
    return ret != -1;
}

// ========== 工具函数：拼接路径 ==========
std::string get_full_path(const std::string& filename) {
    return OUTPUT_DIR + filename;
}

// ========== 核心优化：自动递增文件名生成 ==========
std::string generate_incremental_filename(const std::string& base_name) {
    int max_index = 0;
    DIR* dir = opendir(OUTPUT_DIR.c_str());
    if (!dir) {
        return get_full_path(base_name + "_1.txt");
    }

    struct dirent* entry;
    std::regex file_regex(base_name + R"(_(\d+)\.txt)");
    std::smatch match;

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;
        std::string filename = entry->d_name;
        if (std::regex_match(filename, match, file_regex) && match.size() == 2) {
            try {
                int index = std::stoi(match[1].str());
                max_index = std::max(max_index, index);
            } catch (...) {
                continue;
            }
        }
    }
    closedir(dir);

    return get_full_path(base_name + "_" + std::to_string(max_index + 1) + ".txt");
}

// ========== 持久化：仅保存默认包名 ==========
bool save_default_process_to_file() {
    if (g_default_process.empty()) return false;
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "w");
    if (!fp) return false;
    fprintf(fp, "%s", g_default_process.c_str());
    fclose(fp);
    return true;
}

// ========== 持久化：仅加载默认包名 ==========
bool load_default_process_from_file() {
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "r");
    if (!fp) return false;

    char process_buf[256] = {0};
    if (fgets(process_buf, sizeof(process_buf), fp) == nullptr) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    g_default_process = std::string(process_buf).erase(std::string(process_buf).find_last_not_of("\n\r") + 1);
    return memtool::base::get_pid(g_default_process.c_str()) != -1;
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

// ========== 指针链格式化 ==========
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

// ========== 新增：计算指针链长度（按偏移次数，"->"的个数） ==========
size_t get_chain_length(const std::string& chain) {
    return std::count(chain.begin(), chain.end(), '-') / 2;
}

// ========== 新增：提取指针链中的所有偏移值（用于排序） ==========
std::vector<uint64_t> extract_offsets(const std::string& chain) {
    std::vector<uint64_t> offsets;
    std::regex offset_regex(R"(\+0x([0-9A-Fa-f]+))");  // 匹配 +0x开头的偏移
    std::smatch match;
    std::string temp = chain;

    // 提取所有偏移值并转换为uint64_t
    while (std::regex_search(temp, match, offset_regex)) {
        try {
            uint64_t offset = std::stoull(match[1].str(), nullptr, 16);
            offsets.push_back(offset);
        } catch (...) {
            offsets.push_back(UINT64_MAX);  // 解析失败时设为最大值，排在后面
        }
        temp = match.suffix().str();
    }

    return offsets;
}

// ========== 新增：排序函数（先按长度升序，长度相同按偏移升序） ==========
bool compare_chain(const std::string& a, const std::string& b) {
    size_t len_a = get_chain_length(a);
    size_t len_b = get_chain_length(b);

    // 第一步：按长度升序
    if (len_a != len_b) {
        return len_a < len_b;
    }

    // 第二步：长度相同时，按偏移值逐个对比升序
    std::vector<uint64_t> offsets_a = extract_offsets(a);
    std::vector<uint64_t> offsets_b = extract_offsets(b);

    // 取最短的偏移列表长度进行对比
    size_t min_offset_count = std::min(offsets_a.size(), offsets_b.size());
    for (size_t i = 0; i < min_offset_count; ++i) {
        if (offsets_a[i] != offsets_b[i]) {
            return offsets_a[i] < offsets_b[i];
        }
    }

    // 偏移完全相同（或一方是另一方的前缀），短的在前（理论上长度已相同，此处防异常）
    return offsets_a.size() < offsets_b.size();
}

// ========== 读取指针链文件内容（去重） ==========
std::set<std::string> read_pointer_chain_file(const std::string& file_path) {
    std::set<std::string> chains;
    FILE* fp = fopen(file_path.c_str(), "r");
    if (!fp) {
        std::cerr << "错误：无法打开文件 " << file_path << "\n";
        return chains;
    }

    char buf[1024] = {0};
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        std::string line = buf;
        // 去除换行符和首尾空格（保留中间偏移分隔符）
        line.erase(line.find_last_not_of("\n\r") + 1);
        line.erase(0, line.find_first_not_of(" "));
        line.erase(line.find_last_not_of(" ") + 1);
        if (!line.empty()) {
            chains.insert(line);
        }
    }
    fclose(fp);
    return chains;
}

// ========== 获取目录下指定前缀的所有指针链文件（按序号排序） ==========
std::vector<std::string> get_sorted_chain_files(const std::string& prefix = "pointer_chains") {
    std::vector<std::pair<int, std::string>> file_list;
    DIR* dir = opendir(OUTPUT_DIR.c_str());
    if (!dir) {
        return {};
    }

    struct dirent* entry;
    std::regex file_regex(prefix + R"(_(\d+)\.txt)");
    std::smatch match;

    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;
        std::string filename = entry->d_name;
        if (std::regex_match(filename, match, file_regex) && match.size() == 2) {
            try {
                int index = std::stoi(match[1].str());
                file_list.emplace_back(index, filename);
            } catch (...) {
                continue;
            }
        }
    }
    closedir(dir);

    // 按序号升序排序
    std::sort(file_list.begin(), file_list.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });

    // 提取文件名（带路径）
    std::vector<std::string> result;
    for (const auto& [index, filename] : file_list) {
        result.push_back(get_full_path(filename));
    }
    return result;
}

// ========== 功能4 - 指针链文件对比（长度+偏移排序，移除长度标注） ==========
void compare_chain_files() {
    if (!create_output_dir()) return;

    std::cout << "\n===== 指针链文件对比功能 =====\n";
    std::cout << "对比规则：找出两个文件中的 共有项、新增项、缺失项（最短链在前，长度相同时按偏移升序）\n";
    std::cout << "支持格式：pointer_chains_*.txt / pointer_chains_dual_*.txt\n";

    // 步骤1：选择对比文件类型（普通/双地址）
    int file_type = readInt<int>("请选择文件类型（1=普通指针链，2=双地址指针链，默认1）：", 1);
    std::string file_prefix = (file_type == 2) ? "pointer_chains_dual" : "pointer_chains";

    // 步骤2：获取所有符合条件的文件
    std::vector<std::string> sorted_files = get_sorted_chain_files(file_prefix);
    if (sorted_files.size() < 2) {
        std::cerr << "错误：目录下至少需要2个" << file_prefix << "_*.txt文件才能对比\n";
        std::cerr << "当前目录下的文件：\n";
        for (const auto& file : sorted_files) {
            std::cerr << "- " << file << "\n";
        }
        return;
    }

    // 步骤3：选择对比文件（默认最新两个）
    std::cout << "\n当前可用的" << file_prefix << "文件（按序号排序）：\n";
    for (size_t i = 0; i < sorted_files.size(); ++i) {
        std::cout << i + 1 << ". " << sorted_files[i] << "\n";
    }

    std::string choice = readStringWithDefault(
        "请选择要对比的两个文件（格式：序号1 序号2，默认对比最后两个）",
        std::to_string(sorted_files.size() - 1) + " " + std::to_string(sorted_files.size())
    );

    // 解析选择的序号
    size_t idx1 = 0, idx2 = 0;
    try {
        size_t space_pos = choice.find(' ');
        if (space_pos == std::string::npos) throw std::invalid_argument("");
        idx1 = std::stoull(choice.substr(0, space_pos)) - 1;
        idx2 = std::stoull(choice.substr(space_pos + 1)) - 1;

        if (idx1 >= sorted_files.size() || idx2 >= sorted_files.size() || idx1 == idx2) {
            throw std::out_of_range("");
        }
    } catch (...) {
        std::cerr << "输入格式错误，自动使用最后两个文件对比\n";
        idx1 = sorted_files.size() - 2;
        idx2 = sorted_files.size() - 1;
    }

    std::string file_a = sorted_files[idx1];
    std::string file_b = sorted_files[idx2];
    std::cout << "\n正在对比：\n";
    std::cout << "文件A（基准）：" << file_a << "\n";
    std::cout << "文件B（对比）：" << file_b << "\n";

    // 步骤4：读取两个文件的指针链
    std::cout << "正在读取文件内容...\n";
    std::set<std::string> chains_a = read_pointer_chain_file(file_a);
    std::set<std::string> chains_b = read_pointer_chain_file(file_b);

    if (chains_a.empty() && chains_b.empty()) {
        std::cerr << "错误：两个文件均为空，无法对比\n";
        return;
    } else if (chains_a.empty()) {
        std::cerr << "警告：文件A为空，仅显示文件B的内容\n";
    } else if (chains_b.empty()) {
        std::cerr << "警告：文件B为空，仅显示文件A的内容\n";
    }

    // 步骤5：计算差异
    std::vector<std::string> common_chains;    // 共有项
    std::vector<std::string> only_a_chains;    // A独有的（缺失项）
    std::vector<std::string> only_b_chains;    // B独有的（新增项）

    for (const auto& chain : chains_a) {
        if (chains_b.count(chain)) {
            common_chains.push_back(chain);
        } else {
            only_a_chains.push_back(chain);
        }
    }

    for (const auto& chain : chains_b) {
        if (!chains_a.count(chain)) {
            only_b_chains.push_back(chain);
        }
    }

    // ========== 核心优化：先按长度升序，长度相同按偏移升序 ==========
    std::sort(common_chains.begin(), common_chains.end(), compare_chain);
    std::sort(only_a_chains.begin(), only_a_chains.end(), compare_chain);
    std::sort(only_b_chains.begin(), only_b_chains.end(), compare_chain);

    // 步骤6：生成对比报告（移除长度标注）
    std::string report_file = generate_incremental_filename("chain_compare");
    FILE* fp = fopen(report_file.c_str(), "w+");
    if (!fp) {
        std::cerr << "错误：无法创建对比报告文件 " << report_file << "\n";
        return;
    }

    // 写入报告内容（移除所有长度标注）
    fprintf(fp, "===== 指针链文件对比报告 =====\n");
    fprintf(fp, "基准文件（A）：%s\n", file_a.c_str());
    fprintf(fp, "对比文件（B）：%s\n", file_b.c_str());
    fprintf(fp, "对比时间：%s\n", __TIME__);
    fprintf(fp, "排序规则：按指针链长度升序，长度相同时按偏移值升序\n");
    fprintf(fp, "\n【统计信息】\n");
    fprintf(fp, "文件A指针链总数：%zu\n", chains_a.size());
    fprintf(fp, "文件B指针链总数：%zu\n", chains_b.size());
    fprintf(fp, "共有指针链数：%zu\n", common_chains.size());
    fprintf(fp, "文件A独有的指针链数（缺失项）：%zu\n", only_a_chains.size());
    fprintf(fp, "文件B独有的指针链数（新增项）：%zu\n", only_b_chains.size());

    fprintf(fp, "\n【共有指针链】\n");
    for (size_t i = 0; i < common_chains.size(); ++i) {
        fprintf(fp, "%zu. %s\n", i + 1, common_chains[i].c_str());  // 移除长度标注
    }

    fprintf(fp, "\n【文件A独有的指针链（B中缺失）】\n");
    for (size_t i = 0; i < only_a_chains.size(); ++i) {
        fprintf(fp, "%zu. %s\n", i + 1, only_a_chains[i].c_str());  // 移除长度标注
    }

    fprintf(fp, "\n【文件B独有的指针链（A中新增）】\n");
    for (size_t i = 0; i < only_b_chains.size(); ++i) {
        fprintf(fp, "%zu. %s\n", i + 1, only_b_chains[i].c_str());  // 移除长度标注
    }

    fclose(fp);

    // 步骤7：控制台输出摘要（移除长度标注）
    std::cout << "\n===== 对比完成 =====\n";
    std::cout << "【统计摘要】\n";
    std::cout << "文件A指针链总数：" << chains_a.size() << "\n";
    std::cout << "文件B指针链总数：" << chains_b.size() << "\n";
    std::cout << "共有指针链数：" << common_chains.size() << "\n";
    std::cout << "文件A独有的指针链数（缺失项）：" << only_a_chains.size() << "\n";
    std::cout << "文件B独有的指针链数（新增项）：" << only_b_chains.size() << "\n";
    
    if (!common_chains.empty()) {
        std::cout << "\n【前10条最短共有链】\n";
        size_t max_show = std::min(static_cast<size_t>(10), common_chains.size());
        for (size_t i = 0; i < max_show; ++i) {
            std::cout << i + 1 << ". " << common_chains[i] << "\n";  // 移除长度标注
        }
    }
    
    std::cout << "\n完整对比报告已保存至：" << report_file << "\n";
}

// ========== 功能1：单地址扫描 ==========
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
    std::string output_file = generate_incremental_filename("pointer_chains");
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

// ========== 功能2：双地址查找 ==========
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

    std::string txt_path = generate_incremental_filename("pointer_chains_dual");
    FILE* txt_file = fopen(txt_path.c_str(), "w+");
    if (!txt_file) {
        std::cerr << "错误：无法创建文本文件 " << txt_path << "\n";
        fclose(temp_bin);
        return;
    }

    auto start_gen = std::chrono::high_resolution_clock::now();
    size_t total_chain = scanner.scan_pointer_chain(target_addrs, max_depth, max_offset, false, chain_limit, temp_bin);
    scanner.scan_pointer_chain_to_txt(target_addrs, max_depth, max_offset, false, 0, txt_file);
    
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

// ========== 功能3：设置默认包名 ==========
void set_default_process() {
    std::cout << "\n===== 设置默认包名/进程名 =====\n";
    std::string process = readStringWithDefault("请输入默认进程名（无需输入PID）", g_default_process.empty() ? "无" : g_default_process);
    if (process == "无") {
        std::cerr << "未输入进程信息，设置取消\n";
        return;
    }

    int pid = memtool::base::get_pid(process.c_str());
    if (pid != -1) {
        g_default_process = process;
        printf("设置成功！默认包名: %s（当前PID: %d）\n", process.c_str(), pid);
        if (save_default_process_to_file()) {
            std::cout << "默认包名已保存，下次启动自动加载\n";
        }
    } else {
        std::cerr << "错误：无法找到进程 " << process << "，设置失败\n";
    }
}

}  // namespace

// ========== 主函数 ==========
int main() {
    std::cout << "===== 内存指针链分析工具（仓库适配最终版）=====\n";
    std::cout << "适配仓库：https://github.com/sycmi/6666.git\n";
    std::cout << "所有文件保存至：" << OUTPUT_DIR << "\n";

    if (!create_output_dir()) {
        std::cerr << "程序启动失败：无法创建输出文件夹\n";
        return 1;
    }

    if (load_default_process_from_file()) {
        int current_pid = memtool::base::get_pid(g_default_process.c_str());
        std::cout << "已加载默认包名：" << g_default_process << " | 当前PID: " << current_pid << "\n";
    } else {
        std::cout << "未找到保存的默认包名\n";
    }

    int pid = -1;
    std::string prompt = "请输入目标进程名（无需输入PID）（";
    prompt += g_default_process.empty() ? "无默认，留空仅扫描/查找功能可用" : "回车使用默认[" + g_default_process + "]";
    prompt += "）：";

    std::string process_input;
    std::cout << prompt;
    std::getline(std::cin, process_input);

    if (!process_input.empty()) {
        pid = memtool::base::get_pid(process_input.c_str());
        if (pid != -1) {
            g_default_process = process_input;
            printf("成功附加进程: %s | 当前PID: %d\n", process_input.c_str(), pid);
            save_default_process_to_file();
        } else {
            std::cerr << "警告：无法找到进程 " << process_input << "，仅扫描/查找功能可用\n";
        }
    } else {
        if (!g_default_process.empty()) {
            pid = memtool::base::get_pid(g_default_process.c_str());
            if (pid != -1) {
                std::cout << "已使用默认包名: " << g_default_process << " | 当前PID: " << pid << "\n";
            } else {
                std::cerr << "警告：默认包名 " << g_default_process << " 对应的进程未运行\n";
            }
        } else {
            std::cerr << "未输入进程信息，仅扫描/查找功能可用\n";
        }
    }

    int choice = 0;
    while (true) {
        std::cout << "\n===== 功能菜单 =====\n";
        std::cout << "1. 单地址指针扫描（生成文本文件）\n";
        std::cout << "2. 双地址指针链查找（生成二进制+文本文件）\n";
        std::cout << "3. 修改默认包名（无需输入PID）\n";
        std::cout << "4. 指针链文件对比（最短链在前，偏移升序）\n";
        std::cout << "5. 退出程序\n";
        choice = readInt<int>("请输入功能选项 [1-5]（默认5）：", 5);

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
                pid = memtool::base::get_pid(g_default_process.c_str());
                break;
            case 4:
                compare_chain_files();
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
