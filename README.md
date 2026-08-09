# Network-Engineering-Notes

> **面向对象**：企业网络安全工程师、内网渗透测试学习者、红蓝队技术爱好者。
>
> **核心定位**：深入研究 TCP/IP 协议栈、数据包分析、企业网络安全基础架构，以及内网渗透实战技术（信息收集 → 提权 → 横向移动 → 域渗透）。本仓库定位为**持续迭代的安全工程与攻击技术知识库**。


## ⚠️ 安全声明（请务必阅读）

**本仓库所有内容（含代码片段与攻击手法描述）仅供安全研究和授权测试环境下的教育用途。**
严禁将其中任何技术用于未经授权的网络入侵、数据窃取或系统破坏行为。使用者须遵守所在地法律法规，因违规操作产生的一切法律后果由行为人自行承担。


## 关于本仓库

本仓库记录网络工程、企业安全方向的学习过程及内网渗透实战经验。所有知识点遵循统一的纵深分析流程：

**协议原理** → **协议实现机制** → **数据包抓取与分析** → **攻击面分析** → **防御方案设计 → 绕过与对抗思路**

其中，`07-Offensive-Playbook` 目录将上述流程中的“攻击面分析”进一步深化为**可复用的攻击脚本与实战战术**。


## 仓库状态

**当前版本**：`v1.5` —— 网络基础 + 渗透测试实战起步

**当前建设重点**：
- TCP/IP 协议体系与通信机制
- 数据包抓取与深度分析
- 网络协议攻击面分析（ARP/DNS/DHCP/TCP）
- 企业网络基础架构与防护机制
- **内网渗透实战**：信息收集、提权、横向移动入门（详见 `07-Offensive-Playbook`）

**后续版本规划**：

| 版本 | 主题 | 状态 |
|:---|:---|:---:|
| v1.0 | 网络基础与协议分析 | ✅ 已完成 |
| v1.5 | 网络协议攻击实战（ARP/DNS/DHCP攻击） | ✅ 已完成 |
| **v2.0** | **内网渗透实战（提权/横向/域渗透）** | 🚀 **进行中** |
| v3.0 | 操作系统安全（Windows Internals / Linux Security） | 📋 规划中 |
| v4.0 | Active Directory 域安全（NTLM / Kerberos / LDAP / GPO） | 📋 规划中 |
| v5.0 | 企业身份安全（零信任 / PAM / IAM） | 📋 规划中 |


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
├── 05-Packet-Analysis/              # 数据包分析（工具篇）
│   ├── Wireshark.md
│   └── tcpdump.md
│
├── 06-Network-Security/             # 网络安全攻防分析
│   ├── Layer2-Attacks/              # 二层攻击（ARP/DHCP/VLAN）
│   ├── Protocol-Attacks/            # 协议攻击（DNS/ICMP/TCP）
│   └── Defense/                     # 防御机制（防火墙/IDS/网络分段）
│
├── 07-Offensive-Playbook/           # ⭐ 渗透测试实战手册（红队视角）
│   ├── 01-Reconnaissance/           # 信息收集（多线程扫描/ARP侦察）
│   ├── 02-Privilege-Escalation/     # 提权笔记（Windows/Linux）
│   │   ├── Windows/
│   │   └── Linux/
│   ├── 03-Lateral-Movement/         # 横向移动（SMB/PsExec/WMI）
│   ├── 04-Tunneling/                # 隧道代理（ICMP/DNS/FRP/SSH）
│   ├── 05-Active-Directory/         # 域渗透（Kerberoasting/BloodHound）
│   ├── 06-Code-Snippets/            # 手搓Python攻击脚本（Python 3.10+）
│   └── assets/
│       └── cheatsheets/             # 协议速查表与工具命令速记
│
└── assets/                          # 实验资料（拓扑/截图/抓包文件）
    ├── packet-capture/
    ├── screenshots/
    ├── topology/                    # 含Eve-NG拓扑导出文件及Visio图
    └── diagrams/
```


## 学习方法（安全工程分析流程）

每个知识点严格按照以下纵深模型展开研究，以 **ARP协议** 为例：

| 步骤 | 研究内容 | ARP实例 |
|:---:|:---|:---|
| ① | **协议原理** | RFC 826 定义的请求/响应机制 |
| ② | **实现机制** | 广播请求、单播响应、缓存表老化 |
| ③ | **数据包分析** | Wireshark 抓取 ARP Request/Reply 观察字段 |
| ④ | **攻击面分析** | ARP Spoofing 篡改缓存表实现中间人 |
| ⑤ | **防御方案** | DAI（动态ARP检测）+ DHCP Snooping |
| ⑥ | **对抗视角** | 为何静态ARP绑定无法防御DAI环境下的攻击？ |


## 实验环境（技术栈与隔离要求）

> **⚠️ 严格隔离警告**：所有实验须运行在**仅主机（Host-Only）** 或**自定义隔离网络**中，**严禁**桥接至物理网卡或接入互联网。

**推荐实验平台与版本**（后续将在`assets/topology`中补充详细拓扑图）：

| 组件 | 技术选型与版本建议 | 角色 |
|:---|:---|:---|
| **虚拟化平台** | VMware Workstation 17.x / Eve-NG 5.x / Proxmox VE 8.x | 基础运行环境 |
| **攻击机** | Kali Linux 2025.x (预装Nmap/Metasploit/BloodHound) | 红队视角操作端 |
| **靶机 - 域控** | Windows Server 2022 (需安装AD DS) | 核心攻击目标 |
| **靶机 - 域内用户机** | Windows 10/11 Enterprise (加入域) | 横向移动跳板 |
| **靶机 - 应用服务器** | Ubuntu 22.04 LTS / Windows Server 2019 | 服务利用与提权 |
| **网络设备** | Cisco IOSv 15.x (L3 Switch) + PfSense 2.7.x (Firewall) | 路由与策略模拟 |

**当前已包含的实操实验**：
- ARP 欺骗中间人攻击（含Python Scapy脚本）
- TCP SYN 多线程端口扫描器
- 内网 ARP 存活扫描器
- DHCP 饿死攻击与防御观察
- VLAN 间路由与ACL阻断实验
- DNS 劫持与隧道搭建（进行中）


## 学习路线（Roadmap）

### 第一阶段：网络基础 ✅
- [x] TCP/IP 模型与OSI模型对照
- [x] 数据封装与解封装过程
- [x] IPv4 地址结构与CIDR
- [x] 子网划分（VLSM）与汇总计算
- [x] ARP 协议工作机制
- [x] DHCP 协议（DORA过程）
- [x] DNS 协议解析流程
- [x] VLAN 原理与802.1Q
- [x] STP（生成树协议）基本原理与安全风险
- [ ] 路由协议（静态路由 / OSPF基础）


### 第二阶段：企业网络安全机制（攻防视角的“靶心”理解）

> **核心理念**：内网渗透的核心在于“绕过”。要绕过防火墙ACL、网络分段（VLAN）和IDS规则，**必须深入理解这些防御机制的策略匹配逻辑与处理流程**（例如：状态防火墙的会话表机制、ACL的通配符匹配顺序、IPS的流量重组窗口）。本阶段**重点理解工作原理与策略逻辑**，具体设备（Cisco/Juniper/PaloAlto）的差异化部署命令按需查阅，不强制记忆。

- [ ] 网络隔离与分段（VLAN + 三层ACL联动）
- [ ] 状态防火墙策略（Stateful vs Stateless）
- [ ] 入侵检测/防御系统（IDS/IPS）规则引擎基础
- [ ] 网络流量监控（NetFlow / sFlow / 端口镜像）


### 第三阶段：内网渗透实战（进行中 🚀）

> **前置依赖**：已完成第一、二阶段核心原理学习，具备Wireshark/tcpdump抓包分析能力。

- [x] 信息收集（多线程TCP扫描、ARP存活探测）
- [x] ARP欺骗与中间人流量嗅探
- [ ] Windows/Linux 提权（进行中）
- [ ] 横向移动（SMB/PsExec/WMI/WinRM）
- [ ] 隧道与代理（ICMP/DNS/SSH/FRP）
- [ ] 域渗透（Kerberoasting / BloodHound 路径分析 / 票据攻击）


### 第四阶段：操作系统与身份安全（规划中）
- [ ] Windows 操作系统安全机制（UAC/令牌/权限）
- [ ] Active Directory 域安全（NTLM/Kerberos/LDAP）
- [ ] 企业身份与访问管理（零信任/PAM/IAM）


## 项目演进目标

```text
网络基础与协议原理
        ↓
协议抓包与工作机制分析
        ↓
协议攻击面挖掘（ARP/DNS/TCP）   ← v1.5 核心
        ↓
企业防御机制原理（ACL/状态防火墙）← 第二阶段核心
        ↓
内网渗透实战（绕过与利用）       ← 🚀 当前所处阶段
        ↓
操作系统与AD域安全底层机制
        ↓
企业安全工程师（攻防兼备紫队思维）
```


## 参考资料与扩展阅读

**基础协议标准**：
- RFC 791 (IPv4), RFC 793 (TCP), RFC 826 (ARP), RFC 1035 (DNS)
- RFC 1918 (私有地址), RFC 4632 (CIDR)

**工程与实战书籍**：
- 《计算机网络：自顶向下方法》（Kurose & Ross）
- 《TCP/IP Illustrated Volume 1》（Stevens）
- 《Red Team Field Manual (RTFM)》
- 《The Hacker Playbook 3》（Peter Kim）

**内网渗透核心工具文档**：
- **Impacket** (GitHub) —— SMB/WMI/Exec 工具套件
- **BloodHound** —— AD 攻击路径分析
- **Mimikatz** / **Rubeus** —— 凭证提取与Kerberos利用
- **MITRE ATT&CK® Enterprise Matrix** —— 战术与技术映射（重点看 TA0007-侦察 / TA0008-横向 / TA0006-凭证访问）

**在线靶场**：
- HackTheBox Academy (Active Directory Pentester Path)
- TryHackMe (Wrecker / Forest 系列)


## 贡献与维护说明

本仓库为个人学习知识库，暂不接受外部PR。如果您发现技术错误或逻辑偏差，欢迎通过 Issues 提交指正，核实后将予以修正并致谢。
