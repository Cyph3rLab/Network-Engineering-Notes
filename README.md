# Network-Engineering-Notes

> 面向企业网络安全工程学习的网络知识库。

>

> 深入研究 TCP/IP、网络协议、数据包分析以及企业网络安全基础架构。

---

## 关于本仓库

本仓库用于记录网络工程与企业安全方向的学习过程，定位为持续迭代的安全工程知识库。

主要目标：

- 理解企业网络通信模型

- 掌握网络协议工作机制

- 分析协议攻击面与安全风险

- 学习企业网络安全防护方案

所有知识点按照以下三个维度进行递进分析：

**协议原理** -> **数据包分析** -> **安全分析**

---

## 仓库状态

本仓库作为持续迭代的安全工程知识库，当前处于第一阶段建设期。

**当前版本：** v1.0 - Network Foundation & Protocol Analysis

**当前重点：**

- TCP/IP 协议体系与通信机制

- 数据包抓取与深度分析

- 网络协议攻击面分析

- 企业网络基础架构与防护机制

**后续版本规划：**

- v1.0 网络基础与协议分析 (当前)

- v2.0 网络安全分析与防御

- v3.0 Operating System Security (Windows Internals / Linux Security / Token / Permission Model)

- v4.0 Active Directory Security (NTLM / Kerberos / LDAP / GPO)

- v5.0 Enterprise Identity Security (Zero Trust / PAM / IAM)

---

## 内容结构

```text

Network-Engineering-Notes/

├── 00-Network-Basics/ # 网络基础

│ ├── OSI-TCPIP-Model.md

│ ├── Data-Encapsulation.md

│ ├── IPv4-Addressing.md

│ ├── Subnetting.md

│ └── Network-Device.md

│

├── 01-Data-Link-Layer/ # 数据链路层

│ ├── ARP.md

│ ├── MAC-Learning.md

│ ├── VLAN.md

│ └── STP.md

│

├── 02-Network-Layer/ # 网络层

│ ├── IP.md

│ ├── ICMP.md

│ ├── Routing.md

│ └── NAT.md

│

├── 03-Transport-Layer/ # 传输层

│ ├── TCP.md

│ └── UDP.md

│

├── 04-Application-Protocols/ # 应用层协议

│ ├── DNS.md

│ ├── DHCP.md

│ └── HTTP.md

│

├── 05-Packet-Analysis/ # 数据包分析

│ ├── Wireshark.md

│ └── tcpdump.md

│

├── 06-Network-Security/ # 网络安全分析

│ ├── Layer2-Attacks/

│ │ ├── ARP-Spoofing.md

│ │ ├── DHCP-Attack.md

│ │ └── VLAN-Attack.md

│ │

│ ├── Protocol-Attacks/

│ │ ├── DNS-Attack.md

│ │ ├── ICMP-Tunnel.md

│ │ └── TCP-Attack.md

│ │

│ └── Defense/

│ ├── Firewall.md

│ ├── IDS-IPS.md

│ └── Network-Segmentation.md

│

└── assets/ # 实验资料

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

---

## 实验环境

所有实验均在隔离的网络环境中完成。实验环境基于虚拟化平台搭建，用于协议验证、安全分析以及防御策略测试。

主要用于：

- 理解协议通信过程

- 验证安全风险

- 分析攻击行为

- 测试防御方案

**当前已包含的实验：**

- ARP 协议分析与抓包

- DHCP 协议分析

- DNS 请求与响应分析

- VLAN 网络隔离实验

- TCP 连接建立与释放分析

- Wireshark / tcpdump 流量分析



---

## 学习路线

### 第一阶段：网络基础

- [ ] TCP/IP 模型

- [ ] 数据封装过程

- [ ] ARP 协议

- [ ] DHCP 协议

- [ ] DNS 协议

- [ ] VLAN/STP 安全

- [ ] 路由协议

### 第二阶段：企业网络安全

- [ ] 网络隔离

- [ ] 防火墙策略

- [ ] 入侵检测 (IDS/IPS)

- [ ] 网络流量监控

### 第三阶段：企业身份安全

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



---

## 项目目标

**最终演进路线：**

```text

网络基础

↓

协议分析

↓

网络安全

↓

Windows系统安全

↓

Active Directory域安全

↓

企业安全工程师

```
