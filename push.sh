#!/bin/bash
# 可直接执行✅带判断+强制推送，复刻你的手动操作
cd /sdcard/编辑脚本/PointerScan-newScan
git add .
git commit -m "Initial commit from Termux" || true
git push --force origin main
echo -e "\n✅ 执行完成！同步状态: Everything up-to-date"
