# 路由协议深度解析：从路由表原理到OSPF/BGP攻击与内网防御实战

> **实验环境**：Ubuntu 22.04 LTS / Kali Linux 2025.1 / Cisco IOS 15.2 / FRRouting 8.5 / Scapy 2.5.0
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。

## 一、核心概念与本质（用分拣中心理解）

**路由** 是指网络设备根据**路由表**中的条目，为每一个IP数据包选择最佳出接口的过程。

把全球互联网比作**联邦快递的全球分拣中心**：
- **数据包** = 包裹。
- **IP地址** = 收件人地址。
- **路由表** = 贴在分拣员桌上的“发件指南”。看到“北京”扔进北京专线，看到未知地址扔进默认传送带。

### 关键辨析（工程师必清）
| 概念 | 英文 | 层面 | 攻击者关注点 |
|:---|:---|:---|:---|
| **路由** | Routing | 控制平面 | 伪造路由更新（OSPF LSA/BGP Update）耗尽CPU或劫持流量 |
| **转发** | Forwarding | 数据平面 | 攻击硬件转发芯片（如CVE-2018-0171，Smart Install） |

## 二、技术原理解剖：路由表的原子结构与匹配算法

### 2.1 路由表的“基因序列”
| 字段 | 含义 | 攻防意义 |
| :--- | :--- | :--- |
| **目标网络/掩码** | 目的地址范围 | 掩码越长优先级越高（LPM算法核心） |
| **管理距离（AD）** | 协议可信度（越小越优） | 直连=0，静态=1，EIGRP=90，OSPF=110。注入低AD路由可覆盖合法路由 |
| **度量值** | 到达目标的代价 | 增大合法路由Metric，引导流量走被控链路 |
| **下一跳** | 要把包发给哪个相邻IP | 下一跳被ARP欺骗，数据即被劫持 |

> **⚠️ 厂商差异**：以上AD值为Cisco标准。华为OSPF=10、RIP=100、Static=60；Juniper使用Preference，OSPF=10。排障时须以具体设备文档为准。

### 2.2 匹配算法：最长前缀匹配（LPM）
路由器不选最宽的，而选最精确的（掩码最长的）。
**安全陷阱**：若攻击者注入一条 `10.0.20.5/32`（主机路由），去往该IP的流量会被送往攻击者指定的下一跳，实现**精细化MITM**，不影响其他业务，极其隐蔽。

## 三、动态路由协议的攻防地图

### 3.1 OSPF —— 内网最常见的攻击目标

OSPF通过组播发送Hello包建立邻居关系。**它默认信任邻居，且认证常被忽略**。

#### 攻击手法：OSPF邻居欺骗 + LSA注入
1. 攻击者在内网拿下一台服务器，开启IP转发。
2. 伪造OSPF Hello报文，宣称自己是“骨干区域”可信路由器。
3. 若OSPF未启用认证，合法路由器会与攻击者建立Full邻接关系。
4. 攻击者发布LSA，宣称自己连接了目标网段且Metric=1。
5. **效果**：所有去往目标网段的流量被引向攻击机，实现MITM。

#### 防御配置（2026年生产标准）
结合SHA-256认证与TTL安全机制（GTSM）构建纵深防御：
```cisco
! 1. 优先使用HMAC-SHA-256认证
key chain OSPF-KEY
 key 1
  cryptographic-algorithm hmac-sha-256
  key-string [secure_password]
!
interface GigabitEthernet0/1
 ip ospf authentication key-chain OSPF-KEY
 ! 2. 启用TTL安全机制（GTSM），强制要求收到的OSPF包TTL=255
 ip ospf ttl-security
 ip ospf 1 area 0
 ip ospf passive-interface        ! 终端接口阻断Hello包发送
```

### 3.2 BGP —— 互联网的“命脉”与“劫持重灾区”

**现代防御——RPKI/ROA（RFC 6480）**：
- **ROA**：IP地址所有者授权特定AS宣告特定前缀。
- **RPKI验证**：路由器在接收BGP路由时，验证 `origin AS` 是否匹配ROA记录，不匹配则拒绝。
- **Cisco配置示例**：
  ```cisco
  bgp rpki server tcp 192.0.2.1 port 323 refresh 600
  bgp bestpath origin-as use rpki
  ```

## 四、高级排障与红队实战场景

### 场景1：利用ICMP重定向绕过网关
> ⚠️ **注意**：现代Windows Vista+和较新Linux内核默认已禁用ICMP重定向接收，此攻击仅在特定老旧设备或未加固终端上有效。

- **原理**：攻击者发送伪造的ICMP Type 5，告诉受害者“去往目标走我这更快”。受害者路由表插入临时主机路由，流量被劫持。
- **防御**：确保终端系统参数 `net.ipv4.conf.all.accept_redirects = 0`。

### 场景2：策略路由（PBR）绕过与uRPF防御
- **PBR原理**：在入接口依据源IP指定出接口，覆盖普通路由表。
- **攻击利用**：在办公网伪造源IP为服务器IP，PBR将包扔到服务器出口，绕过办公网审计。
- **防御方案**：在启用PBR的接口上**同时开启uRPF严格模式**（`ip verify unicast source reachable-via rx`），伪造源IP的包在入接口被直接丢弃。

## 五、避坑指南（资深网工排障血泪史）

### 坑1：认为“Ping通网关”代表“路由通”
网关直连 ≠ 能去其他网段。必须检查默认网关（`0.0.0.0/0`）是否存在。

### 坑2：忽略递归路由查询的性能瓶颈
下一跳若是间接地址，需查两次表。若递归条目失效，首条路由存在包也出不去。**排障**：`show ip route [next-hop-ip]` 验证递归可达性。

### 坑3：混淆“路由策略”与“策略路由”
| 概念 | 层面 | 功能 |
|:---|:---|:---|
| **路由策略** | 控制平面 | 影响路由表的学习和宣告 |
| **策略路由（PBR）** | 数据平面 | 影响数据包的转发路径 |

### 坑4：忽视前缀列表的精确匹配能力
- **ACL**：仅匹配IP地址范围，不区分掩码长度。
- **前缀列表**：同时匹配IP地址和掩码长度。
- **注意**：若想阻止外部注入 `10.0.0.0/8` 的子网路由，需配置 `ip prefix-list DENY-PRIVATE seq 5 deny 10.0.0.0/8 le 32`。在Cisco IOS中，`ge` 值必须大于基础前缀长度，若包含基础前缀本身，直接使用 `le` 即可。

## 六、VRF（虚拟路由转发）—— 路由隔离的安全边界

- **原理**：一台物理路由器上维护多个独立路由表，不同VRF间路由完全隔离。
- **红队视角**：若拿下VRF A中的设备，需通过**VRF间路由泄漏**才能横向移动至VRF B，难度极高。
- **安全价值**：VRF结合MPLS是实现数据中心多租户隔离与网络微分段的核心技术。

## 七、路由安全基线检查清单

| 检查项 | 基线标准（Cisco） | 验证命令 |
|:---|:---|:---|
| OSPF认证 | HMAC-SHA-256优先，MD5保底 | `show ip ospf interface |
| OSPF TTL安全 | 直连邻居间启用 | `show ip ospf interface |
| uRPF严格模式 | 边界接口启用 | `show ip verify unicast source` |
| BGP RPKI | 启用ROA验证 | `show bgp rpki table` |

## 八、参考资料

1. **RFC 2328** — *OSPF Version 2*
2. **RFC 4271** — *A Border Gateway Protocol 4 (BGP-4)*
3. **RFC 5082** — *The Generalized TTL Security Mechanism (GTSM)*
4. **RFC 6480** — *An Infrastructure to Support Secure Internet Routing*（RPKI基础）
5. **MITRE ATT&CK** — *T1557 (Adversary-in-the-Middle)*

---

**总结**：路由是连接整个TCP/IP协议栈的“总纲”。掌握路由，你就掌握了攻击者在网络层做中间人的核心技能。攻击者通过OSPF LSA注入实现精细化MITM，通过ICMP重定向劫持单条流量；防御者必须通过OSPF SHA-256认证、GTSM（TTL安全）、uRPF和RPKI构建纵深防线。建议读者将本文与ARP欺骗、ICMP隧道串联，构建完整的网络层攻防知识体系。

---

*本文修订于2026年8月，基于Ubuntu 22.04 LTS / Cisco IOS 15.2环境验证。路由协议行为因厂商及软件版本存在差异，生产环境中请以具体设备文档为准。*
