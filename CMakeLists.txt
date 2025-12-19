cmake_minimum_required(VERSION 3.10)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)

# 项目定义
project(newscan VERSION 1.0.0 LANGUAGES CXX)

# === 关键修改：删除所有交叉编译设置，并指定原生编译器 ===
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)
# ======================================================

# 设置输出目录（根据你的需要保留或修改）
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/outputs/)

# 包含目录
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/memtool
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/threadpool
    ${CMAKE_CURRENT_SOURCE_DIR}/chainer
)

# 源文件
file(GLOB_RECURSE SOURCES 
    "memtool/memextend.cpp"
    "utils/*.cpp"
    "threadpool/threadpool.cpp"
)

add_executable(newscan ${SOURCES} main.cpp)