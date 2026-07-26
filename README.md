# Network-Engineering-Notes —— 网络工程与内网渗透知识库

> 面向企业网络安全工程与内网渗透学习的知识库。
> 
> 深入研究 TCP/IP、网络协议、数据包分析、企业网络安全基础架构，以及内网渗透实战技术。

---

## 关于本仓库

本仓库用于记录网络工程、企业安全方向的学习过程，以及内网渗透实战经验，定位为持续迭代的安全工程与攻击技术知识库。

主要目标：

- 理解企业网络通信模型
- 掌握网络协议工作机制
- 分析协议攻击面与安全风险
- 学习企业网络安全防护方案
- **内网渗透实战：信息收集 → 提权 → 横向移动 → 域渗透**

所有知识点按照以下三个维度进行递进分析：

**协议原理** -> **数据包分析** -> **安全分析（含攻击与防御）**

---

## 仓库状态

本仓库作为持续迭代的安全工程与攻击技术知识库，当前处于第二阶段建设期。

**当前版本：** v1.5 - 网络基础 + 渗透测试实战起步

**当前重点：**

- TCP/IP 协议体系与通信机制
- 数据包抓取与深度分析
- 网络协议攻击面分析
- 企业网络基础架构与防护机制
- **内网渗透实战：信息收集、提权、横向移动入门（07-Offensive-Playbook）**

**后续版本规划：**

- v1.0 网络基础与协议分析 (已完成)
- v1.5 网络协议攻击实战 (ARP/DNS/DHCP攻击，已完成)
- **v2.0 内网渗透实战 (提权、横向移动、域渗透，进行中)**
- v3.0 Operating System Security (Windows Internals / Linux Security)
- v4.0 Active Directory Security (NTLM / Kerberos / LDAP / GPO)
- v5.0 Enterprise Identity Security (Zero Trust / PAM / IAM)

---

## 内容结构

```text
Network-Engineering-Notes/
│
├── 00-Network-Basics/               # 网络基础
│   ├── OSI-TCPIP-Model.md
│   ├── Data-Encapsulation.md
│   ├── IPv4-Addressing.md
│   ├── Subnetting.md
│   └── Network-Device.md
│
├── 01-Data-Link-Layer/              # 数据链路层
│   ├── ARP.md
│   ├── MAC-Learning.md
│   ├── VLAN.md
│   └── STP.md
│
├── 02-Network-Layer/                # 网络层
│   ├── IP.md
│   ├── ICMP.md
│   ├── Routing.md
│   └── NAT.md
│
├── 03-Transport-Layer/              # 传输层
│   ├── TCP.md
│   └── UDP.md
│
├── 04-Application-Protocols/        # 应用层协议
│   ├── DNS.md
│   ├── DHCP.md
│   └── HTTP.md
│
├── 05-Packet-Analysis/              # 数据包分析
│   ├── Wireshark.md
│   └── tcpdump.md
│
├── 06-Network-Security/             # 网络安全分析
│   ├── Layer2-Attacks/
│   │   ├── ARP-Spoofing.md
│   │   ├── DHCP-Attack.md
│   │   └── VLAN-Attack.md
│   ├── Protocol-Attacks/
│   │   ├── DNS-Attack.md
│   │   ├── ICMP-Tunnel.md
│   │   └── TCP-Attack.md
│   └── Defense/
│       ├── Firewall.md
│       ├── IDS-IPS.md
│       └── Network-Segmentation.md
│
├── 07-Offensive-Playbook/           # ⭐ 渗透测试实战手册
│   ├── 01-Reconnaissance/           # 信息收集（多线程扫描、ARP侦察）
│   ├── 02-Privilege-Escalation/     # 提权笔记（Windows/Linux）
│   │   ├── Windows/
│   │   └── Linux/
│   ├── 03-Lateral-Movement/         # 横向移动（SMB/PsExec/WMI）
│   ├── 04-Tunneling/                # 隧道代理（ICMP/DNS/FRP）
│   ├── 05-Active-Directory/         # 域渗透（Kerberoasting/BloodHound）
│   ├── 06-Code-Snippets/            # 手搓 Python 攻击脚本
│   └── assets/
│       └── cheatsheets/             # 协议速查表
│
└── assets/                          # 实验资料（网络拓扑/截图）
    ├── packet-capture/
    ├── screenshots/
    ├── topology/
    └── diagrams/
```

---

## 学习方法

每个知识点严格按照安全工程分析流程进行展开：

**协议原理** -> **协议实现机制** -> **数据包抓取与分析** -> **攻击面分析** -> **防御方案设计**

### 示例：ARP 分析流程

1. **协议原理**：ARP 协议工作机制
2. **协议实现机制**：广播请求与单播响应
3. **数据包抓取与分析**：Wireshark 抓包分析
4. **攻击面分析**：ARP Spoofing 攻击原理
5. **防御方案设计**：DHCP Snooping / DAI 防御机制
6. **工程实践**：企业交换网络安全加固

> **注**：`07-Offensive-Playbook` 目录中的内容，将把上述流程中的“攻击面分析”进一步深化为“可复用的攻击脚本与实战手法”。

---

## 实验环境

所有实验均在隔离的网络环境中完成。实验环境基于虚拟化平台搭建，用于协议验证、安全分析以及防御策略测试。

主要用于：

- 理解协议通信过程
- 验证安全风险
- 分析攻击行为
- 测试防御方案

**当前已包含的实验：**

- ARP 协议分析与抓包（含 ARP 欺骗攻击代码）
- DHCP 协议分析
- DNS 请求与响应分析
- VLAN 网络隔离实验
- TCP 连接建立与释放分析
- Wireshark / tcpdump 流量分析
- **TCP SYN 端口扫描（多线程版）**
- **内网 ARP 存活扫描器**

---

## 学习路线

### 第一阶段：网络基础 ✅
- [x] TCP/IP 模型
- [x] 数据封装过程
- [x] ARP 协议
- [x] DHCP 协议
- [x] DNS 协议
- [x] VLAN/STP 安全
- [ ] 路由协议

### 第二阶段：企业网络安全（了解概念即可，暂不深入）

> **注**：以下内容属于“蓝队（防守方）”技能。作为渗透测试工程师，现阶段只需理解其**防御原理**（以便后续绕过），不需要掌握具体部署配置。
> 真正要死磕的是下一阶段的“内网渗透实战”。

- [ ] 网络隔离（VLAN/ACL 基本原理）
- [ ] 防火墙策略（知道有状态/无状态防火墙的区别）
- [ ] 入侵检测 (IDS/IPS)（知道有这东西，能识别异常流量）
- [ ] 网络流量监控（知道有 NetFlow、SNMP 即可）

### 第三阶段：内网渗透实战（进行中 🚀）
- [x] 信息收集（多线程 TCP 扫描、ARP 扫描）
- [x] ARP 欺骗与中间人攻击
- [ ] Windows/Linux 提权（进行中）
- [ ] 横向移动
- [ ] 隧道与代理

### 第四阶段：企业身份安全（规划中）
- [ ] Windows Security
- [ ] Active Directory Security
- [ ] Kerberos Authentication
- [ ] Enterprise Identity Security

---

## 参考资料

- RFC 标准文档
- 《计算机网络：自顶向下方法》
- Wireshark 官方文档
- Cisco 网络技术文档
- Microsoft Windows Security Documentation
- **HackTheBox / TryHackMe 内网渗透靶场**

---

## 项目目标

**最终演进路线：**

```text
网络基础
    ↓
协议分析
    ↓
网络安全（攻防视角）
    ↓
内网渗透实战  ← 当前所处阶段
    ↓
Windows 系统安全
    ↓
Active Directory 域安全
    ↓
企业安全工程师（攻防兼备）
```

## 安全声明
本仓库所有内容仅供安全研究和教育用途。请勿将其用于任何非法或未经授权的活动。
