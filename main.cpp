#include "memtool/membase.hpp"
#include "memtool/memextend.hpp"
#include "chainer/ccscan.hpp"  // IWYU pragma: keep
#include "chainer/ccompare.hpp"  // IWYU pragma: keep
#include "utils/cmd_parser.h"
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <limits>  // 新增：用于清空输入缓冲区

using namespace utils;

namespace {

std::string format_chain_line(const std::string &module_name, int module_index,
                              const std::vector<size_t> &offsets) {
  std::ostringstream oss;
  oss << module_name << "[" << module_index << "]";
  if (!offsets.empty()) {
    oss << std::hex << std::uppercase;
    for (size_t i = 0; i < offsets.size(); ++i) {
      oss << (i == 0 ? " + 0x" : " -> + 0x") << offsets[i];
    }
    oss << std::nouppercase << std::dec;
  }
  return oss.str();
}

// 新增：通用整数输入函数（支持回车默认值，输入校验）
template <typename T>
typename std::enable_if<std::is_integral<T>::value, T>::type
readIntInput(const std::string& prompt, T defaultVal = T()) {
    std::string input;
    while (true) {
        std::cout << prompt << "（默认：" << defaultVal << "，直接回车使用默认值）：";
        std::getline(std::cin, input);
        
        // 空输入 → 返回默认值
        if (input.empty()) {
            return defaultVal;
        }

        // 非空输入 → 校验并转换
        try {
            uint64_t val = std::stoull(input);
            if (val > std::numeric_limits<T>::max()) {
                throw std::out_of_range("数值超出范围");
            }
            T result = static_cast<T>(val);
            return result;
        } catch (const std::invalid_argument&) {
            std::cerr << "输入无效，请输入纯数字！" << std::endl;
        } catch (const std::out_of_range&) {
            std::cerr << "数值超出范围，请重新输入！" << std::endl;
        } catch (...) {
            std::cerr << "输入异常，请重新输入！" << std::endl;
        }
    }
}

// 新增：字符串输入函数（支持回车默认值，非空校验）
std::string readStringInput(const std::string& prompt, const std::string& defaultVal = "") {
    std::string input;
    while (true) {
        std::cout << prompt;
        if (!defaultVal.empty()) {
            std::cout << "（默认：" << defaultVal << "，直接回车使用默认值）";
        }
        std::cout << "：";
        std::getline(std::cin, input);

        // 空输入 → 返回默认值（如果有）
        if (input.empty()) {
            if (!defaultVal.empty()) {
                return defaultVal;
            } else {
                std::cerr << "输入不能为空，请重新输入！" << std::endl;
                continue;
            }
        }
        return input;
    }
}

// 新增：地址输入函数（十六进制，强制输入无默认）
std::string readAddressInput(const std::string& prompt) {
    std::string input;
    while (true) {
        std::cout << prompt << "（十六进制，不带0x前缀）：";
        std::getline(std::cin, input);
        
        if (input.empty()) {
            std::cerr << "地址不能为空，请重新输入！" << std::endl;
            continue;
        }

        // 校验是否为纯十六进制字符
        bool isValid = true;
        for (char c : input) {
            if (!isxdigit(static_cast<unsigned char>(c))) {
                isValid = false;
                break;
            }
        }
        if (isValid) {
            return input;
        } else {
            std::cerr << "地址无效，请输入纯十六进制字符（0-9, a-f, A-F）！" << std::endl;
        }
    }
}

}  // namespace

int main(int argc, char *argv[]) {
  // 创建命令行解析器
  CommandLineParser parser("newscan", "高性能内存指针链分析工具");

  // 添加命令行选项（保持不变）
  parser.addOption({'p', "process", "目标进程名称或PID", true, false});
  parser.addOption({'a', "address", "目标地址(16进制，不带0x前缀)", true, false});
  parser.addOption({'d', "depth", "最大搜索深度", true, false, "10"});
  parser.addOption({'o', "offset", "最大偏移量", true, false, "500"});
  parser.addOption({'l', "limit", "结果限制数量", true, false, "0"});
  parser.addOption({'f', "file", "输出文件名", true, false, "pointer_chains.txt"});
  parser.addOption({0, "compare-bin", "比较两份指针链二进制文件", false, false});
  parser.addOption({0, "compare-txt", "比较两份指针链文本文件", false, false});
  parser.addOption({0, "lhs", "旧版指针链二进制文件路径", true, false});
  parser.addOption({0, "rhs", "新版指针链二进制文件路径", true, false});
  parser.addOption({0, "report", "对比输出文件名", true, false,
                    "chain_compare.txt"});
  parser.addOption({'v', "verbose", "详细输出模式", false, false});
  parser.addOption({'h', "help", "显示帮助信息", false, false});

  // 设置用法说明（保持不变）
  parser.setUsage("[扫描] -p <进程名/PID> -a <地址> | "
                  "[对比] (--compare-bin|--compare-txt) --lhs <旧文件> --rhs <新文件>");

  // 解析命令行参数（保持不变）
  if (!parser.parse(argc, argv)) {
    std::cerr << "错误: " << parser.getErrorMessage() << std::endl;
    parser.showHelp();
    return 1;
  }

  // 如果请求帮助，显示帮助信息并退出（保持不变）
  if (parser.hasOption("help")) {
    parser.showHelp();
    return 0;
  }

  bool compare_bin_mode = parser.getBoolOption("compare-bin", false);
  bool compare_txt_mode = parser.getBoolOption("compare-txt", false);
  if (compare_bin_mode || compare_txt_mode) {
    // 对比模式逻辑保持不变，无需修改
    if (!parser.hasOption("lhs") || !parser.hasOption("rhs")) {
      std::cerr << "错误: 对比模式需要提供 --lhs 与 --rhs 选项" << std::endl;
      return 1;
    }

    auto lhs_path = parser.getOptionValue("lhs");
    auto rhs_path = parser.getOptionValue("rhs");

    chainer::ccompare<size_t> comparer;
    chainer::bin_compare_result<size_t> compare_result;

    try {
      if (compare_bin_mode) {
        compare_result = comparer.compare_bin_files(lhs_path, rhs_path);
      } else {
        compare_result = comparer.compare_txt_files(lhs_path, rhs_path);
      }
    } catch (const std::exception &ex) {
      std::cerr << "错误: " << ex.what() << std::endl;
      return 1;
    }

    std::string report_path =
        parser.getOptionValue("report", "chain_compare.txt");
    FILE *report = fopen(report_path.c_str(), "w");
    if (report == nullptr) {
      std::cerr << "警告: 无法创建报告文件: " << report_path << std::endl;
    }

    auto emit_line = [&](const std::string &line) {
      if (report != nullptr) {
        fprintf(report, "%s\n", line.c_str());
      }
    };

    if (compare_bin_mode) {
      emit_line("=== 指针链二进制文件对比结果 ===");
    } else {
      emit_line("=== 指针链文本文件对比结果 ===");
    }
    emit_line("旧文件链数量: " + std::to_string(compare_result.lhs_total));
    emit_line("新文件链数量: " + std::to_string(compare_result.rhs_total));
    emit_line("保持不变链数量: " + std::to_string(compare_result.unchanged));
    emit_line("");

    if (compare_result.modules.empty()) {
      emit_line("未找到共同存在的指针链。");
    } else {
      for (const auto &diff : compare_result.modules) {
        emit_line("模块: " + diff.module_name + "[" +
                  std::to_string(diff.module_index) + "]");
        if (!diff.common.empty()) {
          emit_line("  保持不变的链:");
          for (const auto &chain : diff.common) {
            emit_line("    = " +
                      format_chain_line(diff.module_name, diff.module_index,
                                        chain));
          }
        }
        emit_line("");
      }
    }

    if (report != nullptr) {
      fclose(report);
      printf("对比报告已保存至: %s\n", report_path.c_str());
    }

    return 0;
  }

  // ==============================================
  // 核心修改：全参数 命令行优先 + 交互式输入（支持回车默认）
  // ==============================================
  std::string target_process;
  std::string target_addr_str;
  uint32_t max_depth;
  uint32_t max_offset;

  // 1. 处理目标进程（-p/--process）
  if (parser.hasOption("process")) {
    target_process = parser.getOptionValue("process");
  } else {
    // 修改：使用带默认值的字符串输入函数（此处无默认，强制输入）
    target_process = readStringInput("请输入目标进程名或PID");
  }

  // 2. 处理目标地址（-a/--address）
  if (parser.hasOption("address")) {
    target_addr_str = parser.getOptionValue("address");
  } else {
    // 修改：使用地址专用输入函数（强制十六进制，无默认）
    target_addr_str = readAddressInput("请输入目标地址");
  }

  // 3. 处理最大搜索深度 (-d/--depth)
  if (parser.hasOption("depth")) {
    max_depth = parser.getIntOption("depth", 6);
  } else {
    // 修改：使用带默认值的整数输入函数，回车直接用默认值6
    max_depth = readIntInput<uint32_t>("请输入最大搜索深度", 6);
  }

  // 4. 处理最大偏移量 (-o/--offset)
  if (parser.hasOption("offset")) {
    max_offset = parser.getIntOption("offset", 1024);
  } else {
    // 修改：使用带默认值的整数输入函数，回车直接用默认值1024
    max_offset = readIntInput<uint32_t>("请输入最大偏移量", 1024);
  }

  // 5. 解析进程PID（逻辑保持不变）
  int target_pid = -1;
  try {
    target_pid = std::stoi(target_process);
  } catch (...) {
    target_pid = memtool::base::get_pid(target_process.c_str());
    if (target_pid == -1) {
      std::cerr << "错误: 无法找到进程: " << target_process << std::endl;
      return 1;
    }
  }
  printf("目标 PID: %s -> %d\n", target_process.c_str(), target_pid);

  // 6. 解析目标地址（增加异常捕获，优化错误提示）
  uint64_t target_addr;
  try {
    target_addr = std::stoull(target_addr_str, nullptr, 16);
  } catch (const std::invalid_argument &) {
    std::cerr << "错误: 无效的目标地址（需为16进制，不带0x前缀）：" << target_addr_str << std::endl;
    return 1;
  } catch (const std::out_of_range &) {
    std::cerr << "错误: 目标地址超出范围：" << target_addr_str << std::endl;
    return 1;
  }

  // 7. 获取其他参数（limit/file 保持命令行方式）
  uint32_t result_limit = parser.getIntOption("limit", 0);
  std::string output_file = parser.getOptionValue("file", "pointer_chains.txt");

  // ==============================================
  // 后续逻辑保持不变
  // ==============================================
  // 第二步：初始化扫描器
  memtool::base::target_pid = target_pid;
  chainer::cscan<size_t> scanner;  // 64位进程，32位使用 uint32_t

  // 第三步：获取目标进程内存布局
  memtool::extend::get_target_mem();
  memtool::extend::set_mem_ranges(memtool::Anonymous + memtool::C_alloc +
                                  memtool::C_bss + memtool::C_data);

  // 第四步：扫描潜在指针
  auto start_time = std::chrono::high_resolution_clock::now();
  // 参数：起始地址=0, 结束地址=0(不限制), 全扫描=false, 缓冲区数=10, 缓冲区大小=1MB
  size_t pointer_count = scanner.get_pointers(0, 0, false, 10, 1 << 20);
  printf("发现 %ld 潜在指针\n", pointer_count);

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end_time - start_time);
  printf("扫描时间: %lld 毫秒\n", static_cast<long long>(duration.count()));

  // 第五步：构建指针链
  std::vector<size_t> target_addrs;
  target_addrs.emplace_back(target_addr);

  // 直接输出文本格式（推荐方式，避免中间二进制文件转换）
  FILE *output = fopen(output_file.c_str(), "w+");
  if (output == nullptr) {
    std::cerr << "错误: 无法创建输出文件: " << output_file << std::endl;
    return 1;
  }

  size_t chain_count = scanner.scan_pointer_chain_to_txt(
      target_addrs, max_depth, max_offset, false, result_limit, output);
  printf("找到的指针链总数: %ld\n", chain_count);
  fclose(output);

  /* 方式2: 原始二进制格式（需要二次转换）
  auto f = fopen("1", "wb+");
  auto chaincount =
      t.scan_pointer_chain(addrs, maxDepth, maxOffset, false, 0, f);
  printf("chaincount %ld\n", chaincount); // 10层 偏移500
  fclose(f);
  // 格式化输出
  chainer::cformat<size_t> t2;
  auto f2 = fopen("1", "rb+");

  printf("%ld\n", t2.format_bin_chain_data(f2, "2", false)); // 文件
  // printf("%ld\n", t2.format_bin_chain_data(f2, "2", true)); // 文件夹
  // 需要在当前目录有2文件夹

  fclose(f2);
  */
  
  return 0;
}