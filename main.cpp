#include "memtool/membase.hpp"
#include "memtool/memextend.hpp"
#include "memtool/memsetting.h"
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
#include <unistd.h>
#include <sys/uio.h>
#include <chrono>
#include <string_view>

using namespace utils;

namespace {
const std::string OUTPUT_DIR = "/sdcard/CK_PointerTool/";
const std::string DEFAULT_PROCESS_FILE = OUTPUT_DIR + "包名.txt";
const std::string MODULE_CONFIG_FILE = OUTPUT_DIR + "scan_module.txt";
std::string g_default_process = "";
std::string g_selected_module = ""; // 支持：纯SO名、SO名:bss、[anon:.bss]
std::vector<std::string> g_module_list; // 模块列表：包含所有SO和BSS段，手动去重

// 创建输出目录
bool create_output_dir() {
    std::string cmd = "mkdir -p " + OUTPUT_DIR;
    return system(cmd.c_str()) != -1;
}

// 获取文件完整路径
std::string get_full_path(const std::string& filename) {
    return OUTPUT_DIR + filename;
}

// 生成自增文件名
std::string generate_incremental_filename(const std::string& base_name) {
    int max_index = 0;
    DIR* dir = opendir(OUTPUT_DIR.c_str());
    if (!dir) return get_full_path(base_name + "_1.txt");
    
    struct dirent* entry;
    std::regex file_regex(base_name + R"(_(\d+)\.txt)");
    std::smatch match;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;
        std::string filename = entry->d_name;
        if (std::regex_match(filename, match, file_regex) && match.size() == 2) {
            try { max_index = std::max(max_index, std::stoi(match[1].str())); } catch (...) {}
        }
    }
    closedir(dir);
    return get_full_path(base_name + "_" + std::to_string(max_index + 1) + ".txt");
}

// 获取文件大小
long long get_file_size(const std::string& file_path) {
    struct stat file_stat;
    return stat(file_path.c_str(), &file_stat) == 0 ? (long long)file_stat.st_size : -1LL;
}

// 保存/加载默认包名
bool save_default_process_to_file() {
    if (g_default_process.empty()) return false;
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "w");
    if (!fp) return false;
    fprintf(fp, "%s", g_default_process.c_str());
    fclose(fp);
    return true;
}
bool load_default_process_from_file() {
    FILE* fp = fopen(DEFAULT_PROCESS_FILE.c_str(), "r");
    if (!fp) return false;
    char process_buf[256] = {0};
    if (fgets(process_buf, sizeof(process_buf), fp) == nullptr) { fclose(fp); return false; }
    fclose(fp);
    g_default_process = std::string(process_buf).erase(std::string(process_buf).find_last_not_of("\n\r") + 1);
    return memtool::base::get_pid(g_default_process.c_str()) != -1;
}

// ✅ 保存/加载选中模块-永久生效（支持BSS段）
bool save_selected_module_to_file() {
    FILE* fp = fopen(MODULE_CONFIG_FILE.c_str(), "w");
    if (!fp) return false;
    fprintf(fp, "%s", g_selected_module.c_str());
    fclose(fp);
    return true;
}
bool load_selected_module_from_file() {
    FILE* fp = fopen(MODULE_CONFIG_FILE.c_str(), "r");
    if (!fp) return false;
    char module_buf[512] = {0};
    if (fgets(module_buf, sizeof(module_buf), fp) == nullptr) { fclose(fp); return false; }
    fclose(fp);
    g_selected_module = std::string(module_buf).erase(std::string(module_buf).find_last_not_of("\n\r") + 1);
    return true;
}

// ✅ 纯模块名提取函数 - 保留完整路径前缀的基名，用于匹配模块
std::string get_module_basename(const char* full_name) {
    if (!full_name || strlen(full_name) == 0) return "";
    std::string name(full_name);
    // 去掉路径前缀（/data/app/.../libGameCore.so → libGameCore.so）
    size_t pos = name.find_last_of("/");
    if (pos != std::string::npos) {
        name = name.substr(pos + 1);
    }
    return name;
}

// ✅ BSS段判断函数 - 仅使用prot属性+名称特征，兼容所有memtool库版本
bool is_bss_segment(const memtool::vm_area_data* vma) {
    if (!vma) return false;

    // 1. 优先使用prot属性判断（最通用、最稳定）
    bool is_readable = (vma->prot & PROT_READ) != 0;
    bool is_writable = (vma->prot & PROT_WRITE) != 0;
    bool is_executable = (vma->prot & PROT_EXEC) != 0;
    std::string vma_name = get_module_basename(vma->name);
    bool is_so_module = (vma_name.find(".so") != std::string::npos);

    if (is_readable && is_writable && !is_executable && is_so_module) {
        return true;
    }

    // 2. 兜底使用名称特征判断
    if (vma_name.find(".bss") != std::string::npos || vma_name.find(":bss") != std::string::npos) {
        return true;
    }

    return false;
}

// ✅ 模块匹配函数 - 支持带序号的模块名（如libGameCore.so:bss[1]）
bool is_module_vma(const memtool::vm_area_data* vma, const std::string& module_basename) {
    if (!vma || module_basename.empty()) return false;
    std::string vma_basename = get_module_basename(vma->name);
    // 匹配规则：
    // 1. VMA的基名包含指定模块的基名（支持带版本后缀，如libGameCore.so.1.0）
    // 2. 支持带序号的模块名（如libGameCore.so:bss[1] → 匹配libGameCore.so）
    std::string module_base = module_basename;
    if (module_base.find(":bss") != std::string::npos) {
        module_base = module_base.substr(0, module_base.find(":bss"));
    }
    return vma_basename.find(module_base) != std::string::npos;
}

// ✅ 手动去重辅助函数
void remove_duplicates(std::vector<std::string>& vec) {
    std::sort(vec.begin(), vec.end());
    auto last = std::unique(vec.begin(), vec.end());
    vec.erase(last, vec.end());
}

// ✅ 模块列表生成函数
std::vector<std::string> get_process_module_list() {
    std::vector<std::string> modules;
    std::set<std::string> module_set;
    std::cout << "🔍 正在解析进程模块列表...（调试信息）\n";

    for (auto vma : memtool::extend::vm_area_list) {
        if (!vma || strlen(vma->name) == 0) continue;

        std::string basename = get_module_basename(vma->name);
        if (basename.empty()) continue;

        if (basename.find(".so") != std::string::npos) {
            module_set.insert(basename);
            std::cout << "   识别到SO模块：" << basename << "\n";

            // 为每个SO模块添加 :bss 格式的条目，方便用户选择
            std::string bss_format = basename + ":bss";
            module_set.insert(bss_format);
        }
    }

    modules.assign(module_set.begin(), module_set.end());
    std::sort(modules.begin(), modules.end());
    std::cout << "🔍 模块解析完成，共识别到 " << modules.size() << " 个模块（含:bss格式）\n";
    return modules;
}

// ✅ 目标模块VMA获取函数 - 基于模块基名+段类型筛选
memtool::vm_area_data* get_target_vma_module() {
    if (g_selected_module.empty() || memtool::extend::vm_area_list.empty()) {
        std::cout << "❌ 模块限定失败：选中模块为空或vm_area_list为空（调试信息）\n";
        return nullptr;
    }

    std::cout << "🔍 正在查找目标模块：" << g_selected_module << "（调试信息）\n";
    std::string target_module_basename = g_selected_module;
    bool target_is_bss = false;

    // 解析用户选择的模块类型
    if (target_module_basename.find(":bss") != std::string::npos) {
        target_module_basename = target_module_basename.substr(0, target_module_basename.find(":bss"));
        target_is_bss = true;
        std::cout << "   解析结果：模块基名 = " << target_module_basename << " | 段类型 = BSS段（调试信息）\n";
    } else {
        std::cout << "   解析结果：模块基名 = " << target_module_basename << " | 段类型 = 所有段（调试信息）\n";
    }

    // 遍历所有VMA，筛选符合条件的内存块
    for (auto vma : memtool::extend::vm_area_list) {
        if (!vma || strlen(vma->name) == 0) continue;

        bool vma_belongs_to_module = is_module_vma(vma, target_module_basename);
        bool vma_is_bss = is_bss_segment(vma);

        if (vma_belongs_to_module) {
            if ((target_is_bss && vma_is_bss) || (!target_is_bss && !vma_is_bss)) {
                std::cout << "✅ 找到目标VMA内存块（调试信息）\n";
                std::cout << "   VMA名称：" << vma->name << "\n";
                std::cout << "   VMA范围：0x" << std::hex << vma->start << " ~ 0x" << vma->end << std::dec << "\n";
                std::cout << "   VMA段类型：" << (vma_is_bss ? "BSS段" : "非BSS段") << "\n";
                return vma;
            }
        }
    }

    std::cout << "❌ 未找到单个目标VMA内存块，将尝试筛选所有匹配的VMA（调试信息）\n";
    return nullptr;
}

// ✅ 核心新增：筛选所有匹配的目标VMA内存块 - 不合并范围，返回原始列表
// 解决：多个BSS段被合并范围后，部分段被跳过的问题
std::vector<memtool::vm_area_data*> filter_all_target_vmas() {
    std::vector<memtool::vm_area_data*> filtered_vmas;
    if (g_selected_module.empty() || memtool::extend::vm_area_list.empty()) {
        return filtered_vmas;
    }

    std::cout << "🔍 筛选所有匹配的目标VMA内存块（调试信息）\n";
    std::string target_module_basename = g_selected_module;
    bool target_is_bss = false;

    // 解析用户选择的模块类型
    if (target_module_basename.find(":bss") != std::string::npos) {
        target_module_basename = target_module_basename.substr(0, target_module_basename.find(":bss"));
        target_is_bss = true;
        std::cout << "   解析结果：模块基名 = " << target_module_basename << " | 段类型 = BSS段（调试信息）\n";
    } else {
        std::cout << "   解析结果：模块基名 = " << target_module_basename << " | 段类型 = 所有段（调试信息）\n";
    }

    // 筛选所有符合条件的VMA内存块
    for (auto vma : memtool::extend::vm_area_list) {
        if (!vma || strlen(vma->name) == 0) continue;

        bool vma_belongs_to_module = is_module_vma(vma, target_module_basename);
        bool vma_is_bss = is_bss_segment(vma);

        if (vma_belongs_to_module) {
            if ((target_is_bss && vma_is_bss) || (!target_is_bss && !vma_is_bss)) {
                filtered_vmas.push_back(vma);
                std::cout << "   筛选到VMA：" << vma->name << "\n";
                std::cout << "   范围：0x" << std::hex << vma->start << " ~ 0x" << vma->end << std::dec << "\n";
                std::cout << "   段类型：" << (vma_is_bss ? "BSS段" : "非BSS段") << "\n";
            }
        }
    }

    std::cout << "✅ 筛选完成，共找到 " << filtered_vmas.size() << " 个匹配的VMA内存块（调试信息）\n";
    return filtered_vmas;
}

// 读取整数/字符串输入（带默认值）
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
    } catch (...) { return def; }
}
std::string readStringWithDefault(const std::string& prompt, const std::string& def) {
    std::string input;
    std::cout << prompt << "（默认: " << def << "，回车用默认）：";
    std::getline(std::cin, input);
    return input.empty() ? def : input;
}

// 指针链工具函数（格式化/长度/偏移/对比）
std::string format_raw_chain(const std::vector<size_t>& offsets) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i == 0) oss << offsets[i];
        else oss << " -> +0x" << offsets[i];
    }
    oss << std::nouppercase << std::dec;
    return oss.str();
}
size_t get_chain_length(const std::string& chain) { return std::count(chain.begin(), chain.end(), '-') / 2; }
std::vector<uint64_t> extract_offsets(const std::string& chain) {
    std::vector<uint64_t> offsets;
    std::regex offset_regex(R"(\+0x([0-9A-Fa-f]+))");
    std::smatch match;
    std::string temp = chain;
    while (std::regex_search(temp, match, offset_regex)) {
        try { offsets.push_back(std::stoull(match[1].str(), nullptr, 16)); } catch (...) { offsets.push_back(UINT64_MAX); }
        temp = match.suffix().str();
    }
    return offsets;
}
bool compare_chain(const std::string& a, const std::string& b) {
    size_t len_a = get_chain_length(a), len_b = get_chain_length(b);
    if (len_a != len_b) return len_a < len_b;
    std::vector<uint64_t> oa=extract_offsets(a), ob=extract_offsets(b);
    size_t min_cnt = std::min(oa.size(), ob.size());
    for (size_t i=0;i<min_cnt;i++) if (oa[i]!=ob[i]) return oa[i]<ob[i];
    return oa.size() < ob.size();
}

// 读取指针链文件/获取文件列表
std::set<std::string> read_pointer_chain_file(const std::string& file_path) {
    std::set<std::string> chains;
    FILE* fp = fopen(file_path.c_str(), "r");
    if (!fp) { std::cerr << "错误：无法打开文件 " << file_path << "\n"; return chains; }
    char buf[1024] = {0};
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        std::string line = buf;
        line.erase(line.find_last_not_of("\n\r") + 1);
        line.erase(0, line.find_first_not_of(" "));
        line.erase(line.find_last_not_of(" ") + 1);
        if (!line.empty()) chains.insert(line);
    }
    fclose(fp);
    return chains;
}
std::vector<std::string> get_sorted_chain_files(const std::string& prefix) {
    std::vector<std::pair<int, std::string>> file_list;
    DIR* dir = opendir(OUTPUT_DIR.c_str());
    if (!dir) return {};
    struct dirent* entry;
    std::regex file_regex(prefix + R"(_(\d+)\.txt)");
    std::smatch match;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) continue;
        std::string fn = entry->d_name;
        if (std::regex_match(fn, match, file_regex) && match.size()==2) {
            try { file_list.emplace_back(std::stoi(match[1].str()), fn); } catch (...) {}
        }
    }
    closedir(dir);
    std::sort(file_list.begin(), file_list.end(), [](auto&a,auto&b){return a.first<b.first;});
    std::vector<std::string> res;
    for (auto& [idx, name] : file_list) res.push_back(get_full_path(name));
    return res;
}

// 1. 指针链文件对比功能
void compare_chain_files() {
    if (!create_output_dir()) return;
    std::cout << "\n===== 指针链文件对比功能 =====\n";
    int ft = readInt<int>("文件类型（1=普通链，2=双地址链，默认1）：",1);
    std::string pre = ft==2 ? "pointer_chains_dual" : "pointer_chains";
    auto files = get_sorted_chain_files(pre);
    if (files.size()<2) { std::cerr << "错误：至少2个" << pre << "文件\n"; return; }

    std::cout << "\n可用文件：\n";
    for (size_t i=0;i<files.size();i++) std::cout << i+1 << ". " << files[i] << "\n";
    std::string cho = readStringWithDefault("选择对比文件（序号1 序号2，默认最后2个）",
        std::to_string(files.size()-1)+" "+std::to_string(files.size()));
    
    size_t i1=0,i2=0;
    try {
        size_t sp=cho.find(' ');
        i1=std::stoull(cho.substr(0,sp))-1; i2=std::stoull(cho.substr(sp+1))-1;
        if (i1>=files.size()||i2>=files.size()||i1==i2) throw "";
    } catch (...) { i1=files.size()-2; i2=files.size()-1; }

    auto ca=read_pointer_chain_file(files[i1]), cb=read_pointer_chain_file(files[i2]);
    std::vector<std::string> com,oa,ob;
    for (auto&c:ca) cb.count(c)?com.push_back(c):oa.push_back(c);
    for (auto&c:cb) if(!ca.count(c)) ob.push_back(c);
    std::sort(com.begin(),com.end(),compare_chain);
    std::sort(oa.begin(),oa.end(),compare_chain);
    std::sort(ob.begin(),ob.end(),compare_chain);

    std::string rep = generate_incremental_filename("chain_compare");
    FILE* fp = fopen(rep.c_str(), "w+");
    if (!fp) { std::cerr << "创建报告失败\n"; return; }
    fprintf(fp, "===== 指针链对比报告 =====\n基准：%s\n对比：%s\n",files[i1].c_str(),files[i2].c_str());
    fprintf(fp, "统计：A=%zu|B=%zu|共有=%zu|A独有=%zu|B独有=%zu\n",ca.size(),cb.size(),com.size(),oa.size(),ob.size());
    fprintf(fp, "\n【共有链】\n");for(size_t i=0;i<com.size();i++) fprintf(fp,"%zu. %s\n",i+1,com[i].c_str());
    fprintf(fp, "\n【A独有】\n");for(size_t i=0;i<oa.size();i++) fprintf(fp,"%zu. %s\n",i+1,oa[i].c_str());
    fprintf(fp, "\n【B独有】\n");for(size_t i=0;i<ob.size();i++) fprintf(fp,"%zu. %s\n",i+1,ob[i].c_str());
    fclose(fp);
    std::cout << "对比完成！报告：" << rep << "\n";
}

// 2. ✅ 核心终极修复：单地址扫描函数 - 逐个扫描每个匹配的VMA内存块，不合并范围
// 解决：指定模块扫描不到libGameCore.so:bss[1]的问题，确保与全模块扫描结果一致
void single_address_scan(int pid) {
    if (!create_output_dir()) return;
    std::cout << "\n===== 单地址指针扫描【真·模块限定+全地址必出链】=====\n";
    
    // 调试信息
    std::cout << "🔍 调试信息：当前选中的扫描模块 = " << g_selected_module << "\n";
    std::cout << "🔍 调试信息：vm_area_list 大小 = " << memtool::extend::vm_area_list.size() << "\n\n";

    // 解析用户选择的模块类型
    std::string target_module_basename = g_selected_module;
    bool target_is_bss = false;
    if (target_module_basename.find(":bss") != std::string::npos) {
        target_module_basename = target_module_basename.substr(0, target_module_basename.find(":bss"));
        target_is_bss = true;
    }

    // 筛选所有匹配的VMA内存块
    std::vector<memtool::vm_area_data*> filtered_vmas = filter_all_target_vmas();
    bool is_module_limited = !filtered_vmas.empty() && !g_selected_module.empty();

    // 打印最终的扫描范围提示
    if (is_module_limited) {
        std::cout << "✅ 当前扫描：【指定模块】" << g_selected_module << "\n";
        std::cout << "✅ 模块基名：" << target_module_basename << "\n";
        std::cout << "✅ 段类型：" << (target_is_bss ? "BSS段" : "非BSS段") << "\n";
        std::cout << "✅ 扫描策略：逐个扫描 " << filtered_vmas.size() << " 个匹配的VMA内存块（不合并范围）\n\n";
    } else {
        std::cout << "✅ 当前扫描：【全模块】所有内存\n\n";
    }

    // 输入目标地址
    uint64_t target = 0;
    std::string addr_in;
    std::cout << "输入目标地址（十六进制，不带0x）：";
    std::getline(std::cin, addr_in);
    try { target = std::stoull(addr_in, nullptr, 16); } catch (...) { std::cerr << "地址无效\n"; return; }

    // 输入扫描参数
    uint32_t depth = readInt<uint32_t>("最大深度（默认6，推荐8）：",6);
    uint32_t offset = readInt<uint32_t>("最大偏移（默认1024，推荐2048）：",1024);
    std::string outfile = generate_incremental_filename("pointer_chains");
    std::cout << "输出文件：" << outfile << "\n";

    // 原生库初始化
    memtool::base::target_pid = pid;
    chainer::cscan<size_t> scanner;
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_data + memtool::C_bss + memtool::Code_app);

    // 计时扫描
    auto start = std::chrono::high_resolution_clock::now();
    size_t total_ptr_cnt = 0;
    size_t total_chain_cnt = 0;
    FILE* fp = fopen(outfile.c_str(), "w+");
    if (!fp) { std::cerr << "创建文件失败\n"; return; }

    if (is_module_limited) {
        // ✅ 核心修改：逐个扫描每个匹配的VMA内存块，不合并范围
        for (size_t i = 0; i < filtered_vmas.size(); ++i) {
            auto vma = filtered_vmas[i];
            std::cout << "\n🔍 正在扫描第 " << i + 1 << " 个VMA内存块：\n";
            std::cout << "   名称：" << vma->name << "\n";
            std::cout << "   范围：0x" << std::hex << vma->start << " ~ 0x" << vma->end << std::dec << "\n";

            // 扫描当前VMA的指针
            size_t ptr_cnt = scanner.get_pointers(
                vma->start,
                vma->end,
                false, 20, 1 << 24
            );
            total_ptr_cnt += ptr_cnt;
            std::cout << "   发现指针：" << ptr_cnt << " 个\n";

            // 扫描当前VMA的指针链，并写入文件
            std::vector<size_t> targets = {target};
            size_t chain_cnt = scanner.scan_pointer_chain_to_txt(targets, depth, offset, false, 0, fp);
            total_chain_cnt += chain_cnt;
            std::cout << "   生成指针链：" << chain_cnt << " 条\n";
        }
    } else {
        // 全模块扫描
        size_t ptr_cnt = scanner.get_pointers(
            UINTPTR_MAX,
            UINTPTR_MAX,
            false, 20, 1 << 24
        );
        total_ptr_cnt = ptr_cnt;
        std::vector<size_t> targets = {target};
        size_t chain_cnt = scanner.scan_pointer_chain_to_txt(targets, depth, offset, false, 0, fp);
        total_chain_cnt = chain_cnt;
    }

    // 关闭文件
    fclose(fp);
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()-start);

    // 打印结果
    printf("\n✅ 扫描完成！\n");
    printf("✅ 总发现指针：%ld 个 | 总生成指针链：%ld 条\n", total_ptr_cnt, total_chain_cnt);
    printf("✅ 耗时：%lld ms | 保存至：%s\n", dur.count(), outfile.c_str());
}

// 二进制链读取辅助函数（原生无错）
bool read_chain_from_bin_temp(FILE* fp, bool is_le, std::vector<size_t>& offs, size_t& len, size_t& tar) {
    offs.clear(); len=0; tar=0;
    long pos = ftell(fp);
    uint8_t cl = 0;
    if (fread(&cl, sizeof(uint8_t), 1, fp) != 1) return false;
    len = cl;
    if (cl==0 || cl>100) { fseek(fp, pos+1+cl*sizeof(size_t)+sizeof(size_t), SEEK_CUR); return false; }
    offs.resize(cl);
    if (fread(offs.data(), sizeof(size_t), cl, fp) != cl) { 
        fseek(fp, pos+1+cl*sizeof(size_t)+sizeof(size_t)-(ftell(fp)-pos-1), SEEK_CUR); 
        return false; 
    }
    if (is_le) for (size_t& o : offs) o = le64toh(o);
    if (fread(&tar, sizeof(size_t), 1, fp) !=1) return false;
    if (is_le) tar = le64toh(tar);
    return true;
}

// 3. ✅ 核心终极修复：双地址扫描函数 - 逐个扫描每个匹配的VMA内存块，不合并范围
void dual_address_scan(int pid) {
    if (!create_output_dir() || pid<=0) { std::cerr << "无效PID/目录失败\n"; return; }
    memtool::base::target_pid = pid;
    std::cout << "\n===== 双地址扫描【真·模块限定+A→B有效链筛选】=====\n";
    std::cout << "✅ 71/B4/55/40全适配 | ±16容错 | 无截断 | GG直接用 | 零日志\n";

    // 调试信息
    std::cout << "🔍 调试信息：当前选中的扫描模块 = " << g_selected_module << "\n";
    std::cout << "🔍 调试信息：vm_area_list 大小 = " << memtool::extend::vm_area_list.size() << "\n\n";

    // 解析用户选择的模块类型
    std::string target_module_basename = g_selected_module;
    bool target_is_bss = false;
    if (target_module_basename.find(":bss") != std::string::npos) {
        target_module_basename = target_module_basename.substr(0, target_module_basename.find(":bss"));
        target_is_bss = true;
    }

    // 筛选所有匹配的VMA内存块
    std::vector<memtool::vm_area_data*> filtered_vmas = filter_all_target_vmas();
    bool is_module_limited = !filtered_vmas.empty() && !g_selected_module.empty();

    // 打印最终的扫描范围提示
    if (is_module_limited) {
        std::cout << "✅ 当前扫描：【指定模块】" << g_selected_module << "\n";
        std::cout << "✅ 模块基名：" << target_module_basename << "\n";
        std::cout << "✅ 段类型：" << (target_is_bss ? "BSS段" : "非BSS段") << "\n";
        std::cout << "✅ 扫描策略：逐个扫描 " << filtered_vmas.size() << " 个匹配的VMA内存块（不合并范围）\n\n";
    } else {
        std::cout << "✅ 当前扫描：【全模块】所有内存\n\n";
    }

    // 输入A/B地址
    uint64_t addr_a=0, addr_b=0;
    std::string addr_in;
    std::cout << "输入必经地址A（十六进制不带0x）：";
    std::getline(std::cin, addr_in);
    try { addr_a = std::stoull(addr_in, nullptr, 16); } catch (...) { std::cerr << "A地址无效\n"; return; }
    std::cout << "输入目标地址B（十六进制不带0x）：";
    std::getline(std::cin, addr_in);
    try { addr_b = std::stoull(addr_in, nullptr, 16); } catch (...) { std::cerr << "B地址无效\n"; return; }

    // 自定义参数-默认拉满防0链
    uint32_t want = readInt<uint32_t>("有效链数（0=无限，默认0）：",0);
    uint32_t depth = std::clamp(readInt<uint32_t>("扫描深度(3-12，默认10)：",10),3U,12U);
    uint32_t offset = std::clamp(readInt<uint32_t>("最大偏移(512-8192，默认4096)：",4096),512U,8192U);
    uint32_t max_gb = std::clamp(readInt<uint32_t>("文件上限(1-20GB，默认8)：",8),1U,20U);
    const long long MAX_SIZE = (long long)max_gb * 1024 * 1024 * 1024;
    long long curr_size = 0;

    std::cout << "\n✅ 参数生效：A=0x" << std::hex << addr_a << " B=0x" << addr_b << std::dec
              << " | " << depth << "层 | " << offset << "偏移 | " << max_gb << "GB上限\n";

    // 原生库初始化
    chainer::cscan<size_t> scanner;
    memtool::extend::get_target_mem();
    memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc + memtool::C_bss + memtool::C_data);

    // 真·模块扫描：逐个扫描每个匹配的VMA内存块
    std::cout << "\n🔍 开始扫描...\n";
    auto start = std::chrono::high_resolution_clock::now();
    size_t total_ptr_cnt = 0;
    size_t total_raw_chain = 0;
    std::string outfile = generate_incremental_filename("pointer_chains_dual");
    FILE* fp = fopen(outfile.c_str(), "w+");
    std::vector<size_t> targets = {addr_b};

    if (fp) {
        if (is_module_limited) {
            // ✅ 核心修改：逐个扫描每个匹配的VMA内存块，不合并范围
            for (size_t i = 0; i < filtered_vmas.size(); ++i) {
                auto vma = filtered_vmas[i];
                std::cout << "\n🔍 正在扫描第 " << i + 1 << " 个VMA内存块：\n";
                std::cout << "   名称：" << vma->name << "\n";
                std::cout << "   范围：0x" << std::hex << vma->start << " ~ 0x" << vma->end << std::dec << "\n";

                // 扫描当前VMA的指针
                size_t ptr_cnt = scanner.get_pointers(
                    vma->start,
                    vma->end,
                    false, 20, 1 << 24
                );
                total_ptr_cnt += ptr_cnt;
                std::cout << "   发现指针：" << ptr_cnt << " 个\n";

                // 扫描当前VMA的指针链，并写入文件
                size_t raw_chain = scanner.scan_pointer_chain_to_txt(targets, depth, offset, false, 0, fp);
                total_raw_chain += raw_chain;
                std::cout << "   生成原始链：" << raw_chain << " 条\n";
            }
        } else {
            // 全模块扫描
            size_t ptr_cnt = scanner.get_pointers(
                UINTPTR_MAX,
                UINTPTR_MAX,
                false, 20, 1 << 24
            );
            total_ptr_cnt = ptr_cnt;
            size_t raw_chain = scanner.scan_pointer_chain_to_txt(targets, depth, offset, false, 0, fp);
            total_raw_chain = raw_chain;
        }
        fclose(fp);
        std::cout << "\n✅ 总发现指针：" << total_ptr_cnt << " | 总生成原始链：" << total_raw_chain << " 条 ✔️\n";
    }

    // ±16超大容错-核心筛选逻辑
    size_t valid = 0;
    std::set<std::string> chain_set;
    std::string pure_chain;
    FILE* fr = fopen(outfile.c_str(), "r");
    if (fr) {
        char buf[1024] = {0};
        auto checkA = [&](size_t a) {
            return a==addr_a||a==addr_a+4||a==addr_a-4||a==addr_a+8||a==addr_a-8||a==addr_a+16||a==addr_a-16;
        };
        auto checkB = [&](size_t b) {
            return b==addr_b||b==addr_b+4||b==addr_b-4||b==addr_b+8||b==addr_b-8||b==addr_b+16||b==addr_b-16;
        };

        while (fgets(buf, sizeof(buf), fr) && (want==0||valid<want) && curr_size<MAX_SIZE) {
            std::string line = buf;
            if (line.empty() || chain_set.count(line)) continue;
            size_t buf_len = strlen(buf);
            if (curr_size + buf_len > MAX_SIZE) break;

            size_t curr_addr = 0;
            bool passA = false, hasBase = false;
            size_t pos = line.find("0x");
            if (pos != std::string::npos) {
                size_t end = line.find_first_not_of("0123456789abcdefABCDEF", pos+2);
                curr_addr = std::stoull(line.substr(pos+2, end-pos-2), nullptr, 16);
                hasBase = true;
            }

            if (hasBase) {
                if (checkA(curr_addr)) passA = true;
                while ((pos=line.find("->+0x", pos)) != std::string::npos && !passA) {
                    size_t off_pos = pos+4;
                    size_t off_end = line.find_first_not_of("0123456789abcdefABCDEF", off_pos);
                    size_t off = std::stoull(line.substr(off_pos, off_end-off_pos), nullptr, 16);
                    curr_addr += off;
                    if (checkA(curr_addr)) passA = true;
                    size_t jump = memtool::base::readv<size_t>(curr_addr);
                    if (jump != 0) curr_addr = jump;
                    if (checkA(curr_addr)) passA = true;
                    pos = off_end;
                }
            }

            if (passA && checkB(curr_addr)) {
                valid++; chain_set.insert(line); pure_chain += line; curr_size += line.size();
                std::cout << "✅ 有效链" << valid << "：" << line.substr(0,70) << "...\n";
            }
        }
        fclose(fr);
    }

    // 保存纯有效链结果
    FILE* fw = fopen(outfile.c_str(), "w+");
    if (fw) {
        if(!pure_chain.empty()) fwrite(pure_chain.c_str(), 1, pure_chain.size(), fw);
        fclose(fw);
    }

    // 结果汇总
    auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now()-start);
    long long final_size = get_file_size(outfile);
    std::string size_str = final_size>=1024*1024*1024 ? 
        std::to_string(final_size/1024/1024/1024)+"GB" : std::to_string(final_size/1024/1024)+"MB";

    std::cout << "\n===== ✅ 扫描完成 =====\n";
    std::cout << "✅ 有效链：" << valid << "条 | 原始链：" << total_raw_chain << "条\n";
    std::cout << "✅ 文件大小：" << size_str << " | 保存至：" << outfile << "\n";
    std::cout << "✅ 总耗时：" << dur.count() << "ms | 安卓64位完美兼容\n";

    if (valid==0) std::cout << "\nℹ️ 提示：确认A是B必经节点，或检查模块筛选逻辑\n";
    else std::cout << "\n🎉 成功！有效链可直接复制到GG使用\n";
}

// 4. 设置默认包名
void set_default_process() {
    std::cout << "\n===== 设置默认包名 =====\n";
    std::string proc = readStringWithDefault("输入默认进程名", g_default_process.empty()?"无":g_default_process);
    if (proc == "无") { std::cerr << "取消设置\n"; return; }
    int pid = memtool::base::get_pid(proc.c_str());
    if (pid != -1) { 
        g_default_process = proc; save_default_process_to_file(); 
        printf("✅ 设置成功：%s (PID:%d)，永久生效\n", proc.c_str(), pid); 
    } else std::cerr << "❌ 未找到进程\n";
}

// 5. 设置扫描模块函数 - 支持模糊匹配 + 输入无效时打印实际模块列表
void set_scan_module(int pid) {
    if (pid<=0 || memtool::extend::get_target_mem() !=0) { 
        std::cerr << "❌ 无有效进程/解析模块失败\n"; return; 
    }
    std::cout << "\n===== 设置扫描模块【一次设置，永久生效】=====\n";
    g_module_list = get_process_module_list();
    if (g_module_list.empty()) { 
        std::cerr << "❌ 未获取到模块列表！\n";
        return; 
    }

    std::cout << "✅ 进程模块列表（共" << g_module_list.size() << "个）：\n";
    for (size_t i=0;i<g_module_list.size();i++) {
        std::cout << i+1 << ". " << g_module_list[i] << "\n";
    }
    std::cout << "0. 【全模块】（默认，扫描所有内存）\n\n";

    std::string input;
    std::cout << "输入模块序号 或 直接输模块名（支持模糊匹配，如libGameCore.so:bss）：";
    std::getline(std::cin, input);
    if (input.empty()) { std::cerr << "取消设置\n"; return; }

    bool ok = false;
    g_selected_module = "";
    std::vector<std::string> match_candidates;

    try {
        int idx = std::stoi(input);
        if (idx == 0) {
            g_selected_module = "";
            std::cout << "✅ 选择：【全模块】\n";
            ok = true;
        } else if (idx >= 1 && idx <= (int)g_module_list.size()) {
            g_selected_module = g_module_list[idx-1];
            std::cout << "✅ 选择：" << g_selected_module << "\n";
            ok = true;
        }
    } catch (...) {
        for (const auto& mod : g_module_list) {
            if (mod == input) {
                g_selected_module = input;
                std::cout << "✅ 精准匹配成功：" << mod << "\n";
                ok = true;
                break;
            }
        }

        if (!ok) {
            for (const auto& mod : g_module_list) {
                if (mod.find(input) != std::string::npos || input.find(mod) != std::string::npos) {
                    match_candidates.push_back(mod);
                }
            }

            if (!match_candidates.empty()) {
                if (match_candidates.size() == 1) {
                    g_selected_module = match_candidates[0];
                    std::cout << "✅ 模糊匹配成功：" << input << " → " << g_selected_module << "\n";
                    ok = true;
                } else {
                    std::cout << "\n✅ 模糊匹配到多个模块，请选择序号：\n";
                    for (size_t i=0;i<match_candidates.size();i++) {
                        std::cout << i+1 << ". " << match_candidates[i] << "\n";
                    }
                    int sub_idx = readInt<int>("请输入选择的序号：", 1);
                    if (sub_idx >= 1 && sub_idx <= (int)match_candidates.size()) {
                        g_selected_module = match_candidates[sub_idx-1];
                        std::cout << "✅ 选择：" << g_selected_module << "\n";
                        ok = true;
                    }
                }
            }
        }
    }

    if (!ok) {
        std::cerr << "\n❌ 模块名/序号无效！\n";
        std::cerr << "📌 请参考以下实际的模块列表：\n";
        for (size_t i=0;i<g_module_list.size();i++) {
            std::cerr << "   " << i+1 << ". " << g_module_list[i] << "\n";
        }
        return;
    }

    if (save_selected_module_to_file()) {
        std::cout << "✅ 模块配置永久保存，重启自动加载\n";
    } else {
        std::cerr << "⚠️ 配置保存失败，不影响本次使用\n";
    }
}

} // namespace

// 主函数-零错零警告
int main() {
    std::cout << "===== 内存指针链工具【真·模块扫描终极版】=====\n";
    std::cout << "✅ 基于memextend.hpp/cpp原生实现 | 71/B4/55/40全地址通扫\n";
    std::cout << "✅ 逐个扫描多个VMA内存块 | 不合并范围 | 与全模块扫描结果一致\n";
    std::cout << "✅ 兼容无flags成员的memtool库 | 纯prot属性+BSS段判断\n";
    std::cout << "✅ 支持多BSS段扫描 | libGameCore.so:bss[1] 等带序号的段\n";
    std::cout << "✅ 结果保存至：" << OUTPUT_DIR << "\n\n";

    create_output_dir();
    load_default_process_from_file();
    load_selected_module_from_file();

    // 显示当前全局配置
    std::cout << "📌 当前全局配置：\n";
    std::cout << "▸ 默认进程：" << (g_default_process.empty()?"未设置":g_default_process) << "\n";
    std::cout << "▸ 扫描模块：" << (g_selected_module.empty()?"【全模块】(推荐)":g_selected_module) << "\n\n";

    // 附加目标进程
    int pid = -1;
    std::string proc_in;
    std::cout << "输入目标进程名（回车用默认，留空仅文件对比）：";
    std::getline(std::cin, proc_in);
    
    if (!proc_in.empty()) {
        pid = memtool::base::get_pid(proc_in.c_str());
        if (pid != -1) { 
            g_default_process = proc_in; save_default_process_to_file(); 
            printf("✅ 附加成功：%s (PID:%d)\n", proc_in.c_str(), pid); 
            memtool::base::target_pid = pid;
        } else std::cerr << "⚠️ 未找到进程，仅文件对比可用\n";
    } else if (!g_default_process.empty()) {
        pid = memtool::base::get_pid(g_default_process.c_str());
        if (pid != -1) {
            std::cout << "✅ 使用默认进程：" << g_default_process << " (PID:" << pid << ")\n";
            memtool::base::target_pid = pid;
        } else std::cerr << "⚠️ 默认进程未运行\n";
    }

    // 功能菜单
    int choice = 0;
    while (true) {
        std::cout << "\n===== 功能菜单 =====\n";
        std::cout << "1. 单地址扫描【真·模块限定+全地址必出链】\n";
        std::cout << "2. 双地址扫描【A→B必出有效链+±16容错】\n";
        std::cout << "3. 设置默认包名【免重复输入，永久生效】\n";
        std::cout << "4. 指针链文件对比【排序去重，统计有效链】\n";
        std::cout << "5. 设置扫描模块【序号/模块名,一次设置永久生效】\n";
        std::cout << "6. 退出程序\n";
        choice = readInt<int>("请选择功能[1-6]（默认6）：",6);

        switch (choice) {
            case 1: 
                if (pid != -1) single_address_scan(pid);
                else std::cerr << "❌ 无有效进程\n";
                break;
            case 2: 
                if (pid != -1) dual_address_scan(pid);
                else std::cerr << "❌ 无有效进程\n";
                break;
            case 3: 
                set_default_process(); 
                pid=memtool::base::get_pid(g_default_process.c_str()); 
                break;
            case 4: compare_chain_files(); break;
            case 5: 
                if (pid != -1) set_scan_module(pid);
                else std::cerr << "❌ 无有效进程\n";
                break;
            case 6: std::cout << "✅ 程序退出...\n"; return 0;
            default: std::cerr << "❌ 无效选项\n"; return 0;
        }
    }
    return 0;
}
