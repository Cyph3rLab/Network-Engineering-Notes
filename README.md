
# Network-Engineering-Notes

> 面向网络安全工程学习的网络工程知识库，记录 TCP/IP、网络协议、数据包分析以及企业网络基础架构相关知识。

---

## 📌 关于本仓库

本仓库用于记录我在网络工程与网络安全方向的学习过程。

目标是深入理解：

- 企业网络如何通信
- 网络设备如何转发数据
- 协议如何工作
- 网络攻击产生的原因
- 企业环境中的安全防护措施

学习内容主要从三个角度展开：

- 协议原理（Protocol）
- 系统实现（Implementation）
- 安全分析（Security Analysis）

---

## 🗂️ 内容结构

```

Network-Engineering-Notes

├── 01-Data-Link-Layer/
│   ├── ARP
│   ├── MAC地址学习
│   ├── VLAN
│   └── STP
│
├── 02-Network-Layer/
│   ├── IP
│   ├── ICMP
│   ├── Routing
│   └── NAT
│
├── 03-Transport-Layer/
│   ├── TCP
│   └── UDP
│
├── 04-Application-Protocols/
│   ├── DNS
│   ├── DHCP
│   └── HTTP
│
├── 05-Packet-Analysis/
│   ├── Wireshark
│   └── tcpdump
│
└── 06-Network-Security/
├── ARP Spoofing
├── DHCP Attack
└── DNS Security

```

---

## 🔬 学习方法

每个知识点按照以下流程进行分析：

```

协议原理
↓
数据包分析
↓
安全风险分析
↓
防御方案

```

例如：

ARP：

```

ARP工作机制
↓
Wireshark抓包分析
↓
ARP Spoofing风险分析
↓
DHCP Snooping / DAI防御

```

---

## 🧪 实验记录

所有实验均在隔离环境中完成，用于理解协议机制以及验证安全方案。

当前实验：

- ARP协议分析与抓包
- DHCP协议分析
- DNS请求与响应分析
- VLAN网络隔离实验
- TCP连接建立与释放分析
- Wireshark / tcpdump流量分析

---

## 🛠️ 使用工具

| 类型 | 工具 |
|---|---|
| 数据包分析 | Wireshark、tcpdump |
| 网络扫描 | Nmap |
| 虚拟化环境 | VMware、VirtualBox |
| 操作系统 | Linux、Windows |

---

## 🎯 学习路线

- ⬜ TCP/IP基础
- ⬜ ARP协议分析
- ⬜ DHCP/DNS协议分析
- ⬜ VLAN与STP安全
- ⬜ 路由协议
- ⬜ 企业网络架构
- ⬜ 网络安全监控

---

## 📚 参考资料

- RFC标准文档
- 《计算机网络：自顶向下方法》
- Wireshark官方文档
- Cisco网络技术文档
