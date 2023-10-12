# XENBlocks GPU Miner

XENBlocks GPU Miner is a high-performance GPU mining software developed for XENBlocks Blockchain. 
It supports both CUDA and OpenCL, enabling it to run on various GPU architectures.

## Origin & Enhancements

This project is a fork of the original [XENMiner](https://github.com/jacklevin74/xenminer), a CPU miner developed by jacklevin74. We are thankful to jacklevin74 and all contributors to the original project for laying the groundwork.


## 系统要求

Ubuntu 20.04 及以上版本

Python

Nvidia RTX 显卡


## 设置方法

运行初始化脚本 安装依赖

sh init.sh

如果你的显卡不是 30 或者 40系，请自行修改 init.sh 脚本中的 sm_86 选项


tmux 新建一个会话

tmux -u 


修改配置文件中的**钱包地址**与节点地址，以及单张GPU每小时成本（$），用于成本估算


运行主程序

python3 app.py

