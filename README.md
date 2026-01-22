```markdown
# 🔒 可配置网络加密和解密系统的设计与实现 - 毕业设计项目

> 基于Python的多层加密文件传输系统，合肥师范学院本科毕业设计

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

## ✨ 核心功能

### 🔐 安全特性
- **多层加密**：PBKDF2 + AES-GCM/ChaCha20 + RSA混合加密
- **双重隔离**：物理目录隔离 + 数据库权限校验
- **文件拦截**：客户端/服务端双重禁止可执行文件上传
- **实时监控**：数据熵值可视化分析

### 📁 文件管理
- **分块传输**：大文件分块加密上传下载
- **权限控制**：公开分享/私密传输两种模式
- **云端存储**：支持双层加密保护（可选提取码）

### 💬 实时通信
- **加密聊天**：端到端加密实时消息
- **历史记录**：支持聊天记录查询

## 🚀 快速开始

### 1. 环境要求
- Python 3.11+
- Windows/Mac/Linux

### 2. 一键安装
```bash
# 克隆项目
git clone https://github.com/H1deonpussy/SecureFileTransferSystem.git
cd SecureFileTransferSystem

# 安装依赖
pip install -r requirements.txt

# 生成密钥
python rsa_keygen.py
```

### 3. 启动系统
```bash
# 启动服务端（终端1）
python web_server.py

# 启动客户端（终端2）
python client_gui.py
```

## 📖 基本使用

### 第一步：注册登录
1. 启动客户端程序
2. 在"身份认证"页面注册新账户
3. 登录系统

### 第二步：传输文件
1. 切换到"加密传输"页面
2. 选择加密算法（推荐AES-256-GCM）
3. 选择文件并开始上传

### 第三步：查看文件
1. 切换到"云端存储"页面
2. 双击文件进行下载
3. 如需提取码，按提示输入

## 📂 项目结构

```
SecureFileTransferSystem/
├── client_gui.py          # 客户端主界面
├── web_server.py          # 服务端主程序
├── hybrid_engine.py       # 混合加密引擎
├── rsa_keygen.py          # RSA密钥生成
├── log_analyzer.py        # 日志分析器
├── test_suite.py          # 测试套件
├── requirements.txt       # 依赖库
└── README.md              # 说明文档
```

## 🛠️ 技术栈

| 技术 | 用途 |
|------|------|
| Python 3.11 | 主开发语言 |
| Tkinter | 客户端GUI界面 |
| Flask + SocketIO | 服务端实时通信 |
| PyCryptodome | 密码学算法库 |
| SQLite3 | 嵌入式数据库 |
| Matplotlib | 数据可视化 |

## 📝 毕业设计信息

**题目**：可配置网络加密和解密系统的设计与实现  
**学校**：合肥师范学院  
**学院**：计算机学院  
**专业**：计算机科学与技术  
**作者**：崔可幸  
**学号**：2210461231  
**指导教师**：张倩  
**完成时间**：2026年1月

## 🐛 常见问题

### Q1: 启动服务端提示端口占用？
```bash
# 修改端口号
修改 web_server.py 中的 SERVER_PORT = 5004
```

### Q2: 客户端连接失败？
- 确保服务端已启动
- 检查防火墙设置
- 确认网络连接正常

### Q3: 文件上传失败？
- 检查文件是否超过限制
- 确认磁盘空间充足
- 查看日志文件排查问题

## 📞 联系信息

- **作者**：崔可幸
- **电话**：19355174336
- **邮箱**：2399529421@qq.com
- **GitHub**: [H1deonpussy](https://github.com/H1deonpussy)
- **项目地址**: https://github.com/H1deonpussy/SecureFileTransferSystem

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

---
**如果觉得项目不错，请给个 ⭐ Star 支持！**

> 提示：本系统为毕业设计项目，仅供学习和研究使用。
```

### 总结
1. 内容完全保留了原格式，包括徽章、代码块、列表、表格等 Markdown 元素；
2. 代码块均标注了正确的语言类型（bash/无），保证渲染效果；
3. 特殊符号（如 🔒✨🔐 等）和排版结构均完整保留，可直接粘贴到 GitHub 的 README.md 中使用。
