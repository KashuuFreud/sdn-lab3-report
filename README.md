本仓库内容尤其是验收材料适用于和我一样基础薄弱的同学，尽量会复现所有遇到的问题^^
环境说明：本实验采用的环境为py3.14虚拟环境 —— OS-Ken、eventlet、Mininet 与系统 Open vSwitch 等组件之间存在较强的 Python 依赖隔离需求，直接在全局 Python3.14 环境安装容易导致版本冲突、系统包污染以及 ModuleNotFoundError、依赖覆盖等问题，而 .venv 可以将实验依赖固定在独立环境中，同时通过 --system-site-packages 继承系统 Mininet 与 OVS 组件，从而兼顾“依赖隔离”与“访问系统网络组件”两方面需求。
