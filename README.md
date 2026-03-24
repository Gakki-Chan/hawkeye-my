# Hawkeye Simulation

## 项目简介

本项目是一个基于 `ns-3.18` 的网络仿真工程，主要用于 RDMA/Qbb、交换机队列、遥测输出，以及攻击流量和死锁场景相关实验。

当前主要仿真入口：

- `scratch/third.cc`：普通/攻击场景主程序
- `scratch/third_deadlock.cc`：死锁场景主程序

项目中已经提供了两组可参考的实验配置：

- `mix/`
- `mix_deadlock/`

## 已验证环境

- 系统版本：`Ubuntu 20.04.6 LTS`
- 当前整理环境：`WSL2`
- 内核版本：`6.6.87.2-microsoft-standard-WSL2`
- ns-3 版本：`3.18`
- C++ 标准：`GNU++11 / C++11`
- 构建日志中的编译选项：`-std=gnu++11`
- Python 版本：`Python 2.7.18`
- 建议编译器：`gcc-7 / g++-7`

说明：

1. 本仓库的 `waf` 脚本依赖 Python 2，建议使用 `python2 ./waf ...` 执行命令。
2. 当前仓库在默认编译流程下会在 `src/lte/model/epc-tft.cc` 处出现兼容性编译错误，因此更推荐在 `Ubuntu 20.04 + Python 2 + GCC 7` 环境中使用。
3. 历史 `build.log` 中可以看到该工程曾使用 `g++-7` 和 `-std=gnu++11` 进行编译。

## 目录结构

```text
simulation/
├─ scratch/                 # 仿真入口程序
├─ src/                     # ns-3 及项目修改后的模块源码
├─ mix/                     # 普通/攻击场景示例配置与输出目录
├─ mix_deadlock/            # deadlock 场景示例配置与输出目录
├─ wscript / waf            # ns-3 / waf 构建脚本
└─ VERSION                  # ns-3 版本号
```

## 环境配置

推荐在 Ubuntu 20.04 下执行以下命令安装基础依赖：

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  gcc-7 g++-7 \
  python2 python-is-python2 \
  make gdb pkg-config
```

如果你希望额外启用更多 ns-3 可选功能，也可以按需安装：

```bash
sudo apt install -y \
  libboost-all-dev \
  libgtk2.0-dev \
  libxml2-dev \
  libsqlite3-dev
```

建议在当前终端中显式指定编译器：

```bash
export CC=gcc-7
export CXX=g++-7
```

检查环境是否正确：

```bash
python2 --version
gcc-7 --version
g++-7 --version
```

## 配置与编译

进入项目根目录后，先执行配置：

```bash
cd simulation
python2 ./waf configure --disable-python --disable-tests --disable-examples
```

查看可构建目标：

```bash
python2 ./waf list
```

编译常用仿真程序：

```bash
python2 ./waf build --targets=third,third_deadlock -j$(nproc)
```

如果你需要完整编译整个工程，也可以执行：

```bash
python2 ./waf build -j$(nproc)
```

## 运行示例

运行普通/攻击场景：

```bash
python2 ./waf --run "third mix/config.txt"
```

运行 deadlock 场景：

```bash
python2 ./waf --run "third_deadlock mix_deadlock/config.txt"
```


## 配置文件说明

以 `mix/` 为例，常用文件如下：

- `mix/config.txt`：主配置文件
- `mix/config_doc.txt`：配置项说明文档
- `mix/topology.txt`：拓扑定义
- `mix/flow.txt`：流量定义
- `mix/attacker.txt`：攻击流配置
- `mix/trace.txt`：需要监控的节点列表

其中：

- `topology.txt` 第一行通常为：`总节点数 交换机节点数 链路数`
- `flow.txt` 第一行为流数量，后续每行格式为：`src dst pg dport size start_time stop_time`
- `trace.txt` 第一行为需要 trace 的节点数量，后续为节点编号列表

常见输出文件：

- `mix/mix.tr`：分组级 trace 输出
- `mix/fct.txt`：流完成时间
- `mix/pfc.txt`：PFC 结果
- `mix/qlen.txt`：队列长度监控结果
- `mix/data/`：遥测相关输出

`mix_deadlock/` 目录的组织方式与 `mix/` 类似。

## 已知问题

1. `waf` 依赖 Python 2，不建议直接使用 Python 3 运行。
2. 当前代码在构建 `lte` 模块时，可能在 `src/lte/model/epc-tft.cc` 处报 `operator<<` 相关编译错误。
3. 如果你只关注 `third` / `third_deadlock` 仿真，建议优先固定 Ubuntu 20.04、Python 2 和 GCC 7 环境后再编译。

## 参考命令汇总

```bash
cd simulation

export CC=gcc-7
export CXX=g++-7

python2 ./waf configure --disable-python --disable-tests --disable-examples
python2 ./waf list
python2 ./waf build --targets=third,third_deadlock -j$(nproc)

python2 ./waf --run "third mix/config.txt"
python2 ./waf --run "third_deadlock mix_deadlock/config.txt"
```
