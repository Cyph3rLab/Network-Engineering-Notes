# 路由协议深度解析：从路由表原理到OSPF/BGP攻击与内网防御实战


> **实验环境**：Ubuntu 22.04 LTS / Kali Linux 2025.1 / Cisco IOS 15.2 / FRRouting 8.5 / Scapy 2.5.0
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。


## 一、核心概念与本质（用分拣中心理解）

**路由（Routing）** 是指：网络设备（路由器或三层交换机）根据**路由表（Routing Table）** 中的条目，为每一个IP数据包**选择最佳出接口（或下一跳IP）** 的过程。

把全球互联网比作**联邦快递的全球分拣中心**：

- **数据包** = 需要寄送的包裹。
- **IP地址（如 8.8.8.8）** = 收件人的最终地址。
- **路由表** = 贴在分拣员桌子上的“发件指南”：
  - 看到地址是“北京” → 扔进“北京专线”传送带（下一跳）。
  - 看到地址是“上海” → 扔进“上海专线”传送带。
  - 看到地址是“火星” → 扔进“默认传送带（Default Gateway）”（默认路由）。

### 关键辨析（工程师必清）

| 概念 | 英文 | 层面 | 类比 | 攻击者关注点 |
|:---|:---|:---|:---|:---|
| **路由** | Routing | **控制平面（Control Plane）** | “大脑思考”——决定往哪走 | 伪造路由更新（OSPF LSA/BGP Update）耗尽CPU |
| **转发** | Switching/Forwarding | **数据平面（Data Plane）** | “手部动作”——把包从接口扔出去 | 攻击硬件转发芯片（如CVE-2018-0171，Smart Install） |

> **实战意义**：一台路由器可以运行复杂的BGP协议（大脑很累），但如果硬件转发芯片（ASIC）故障，网络依然瘫痪。攻防中，攻击者优先攻击**控制平面**（如伪造OSPF Hello包让CPU满载），因为数据平面的攻击需要物理接触或硬件漏洞，门槛极高。


## 二、技术原理解剖：路由表的原子结构与匹配算法

### 2.1 路由表的“基因序列”

在Cisco设备中输入`show ip route`，或在Linux中输入`ip route show`，每一条路由条目都包含以下四个核心要素：

| 字段 | 含义 | 示例值（Cisco） | 攻防意义 |
| :--- | :--- | :--- | :--- |
| **目标网络/掩码** | 目的地址范围 | `10.0.20.0/24` | 匹配目标IP。**掩码越长，优先级越高**（LPM算法核心） |
| **管理距离（AD）** | 协议可信度（数值越小越可信） | **直连=0**，**静态=1**，**EIGRP=90**，**OSPF=110**，**RIP=120** | 若注入AD<110的伪造路由，可覆盖合法OSPF路由 |
| **度量值（Metric）** | 到达目标的距离/代价（数值越小越优） | OSPF基于带宽（COST=10），RIP基于跳数（Hops=3） | 增大合法路由的Metric，引导流量走备用（被控）链路 |
| **下一跳（Next-Hop）** | 要把包发给哪个相邻IP | `192.168.1.1` | 若下一跳被ARP欺骗，数据即被劫持 |

> **⚠️ 厂商差异重要提示**：以上AD值为**Cisco设备标准**。**华为**：OSPF=10、RIP=100、Static=60；**Juniper**：使用**路由优先级（Preference）** ，OSPF=10、RIP=100。排障时须以具体设备文档为准。

### 2.2 匹配算法：最长前缀匹配（LPM，Longest Prefix Match）

当一个数据包（目标IP为 `10.0.20.5`）进入路由器时，它**不选最宽的，而选最精确的（掩码最长的）** 。

- 路由表有：
  - 路由A：`10.0.0.0/8`（匹配范围 10.0.0.0 ~ 10.255.255.255）
  - 路由B：`10.0.20.0/24`（匹配范围 10.0.20.0 ~ 10.0.20.255）
- **匹配过程**：目标IP `10.0.20.5` 与所有路由条目做“按位与”运算，**两条都匹配**。但路由器选择**掩码更长的 /24**（精确度更高）。

> **安全陷阱（红队必看）** ：若攻击者向内网注入一条 `10.0.20.5/32`（主机路由），所有去往 `10.0.20.5` 的流量都会被送往攻击者指定的下一跳，实现**精细化MITM**，而不影响其他业务（极其隐蔽）。


## 三、动态路由协议的攻防地图

路由分为**静态路由（手动配置）** 和**动态路由（协议自动学习）** 。内网渗透中，攻击者最青睐动态路由协议，因为**它们默认信任邻居，且认证常被忽略**。

### 3.1 静态路由与浮动静态路由

- **特点**：管理员手动配置（`ip route 10.0.20.0 255.255.255.0 192.168.1.1`）。
- **攻击难度**：极高（需登录设备篡改配置）。
- **盲区**：若内网配置了**浮动静态路由**作为备份（AD=200），主链路断开后生效，攻击者无法通过动态路由协议覆盖它（因AD更高）。

### 3.2 OSPF（开放式最短路径优先）—— 内网最常见的攻击目标

OSPF工作在三层，通过组播 `224.0.0.5`（所有OSPF路由器）和 `224.0.0.6`（DR/BDR）发送Hello包建立邻居关系。

#### 攻击手法：OSPF邻居欺骗 + LSA注入

1. 攻击者在内网拿下一台服务器，开启IP转发。
2. 使用工具（**Scapy + OSPF模块**或**FRRouting**）伪造OSPF Hello报文，宣称自己是“骨干区域（Area 0）”中的可信路由器。
3. **致命点**：若OSPF未启用认证（默认明文），合法路由器会“开心地”与攻击者建立Full邻接关系。
4. 攻击者向合法路由器发布 **LSA（链路状态通告）** ，宣称自己连接了目标网段（如 `10.0.30.0/24`）且Metric=1。
5. **效果**：所有去往数据库网段（`10.0.30.0/24`）的流量被引向攻击机，实现**近乎无感的MITM**。

#### 防御配置（2026年生产标准）

```cisco
! 优先使用SHA-256认证（Cisco IOS 15.1+）
key chain OSPF-KEY
 key 1
  cryptographic-algorithm sha-256
  key-string [secure_password]
!
interface GigabitEthernet0/1
 ip ospf authentication sha256 key-chain OSPF-KEY
 ip ospf 1 area 0
 ip ospf passive-interface        ! 终端接口阻断Hello包发送
!
! 若设备不支持SHA，退而使用MD5
interface GigabitEthernet0/1
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 [password]
```

### 3.3 BGP（边界网关协议）—— 互联网的“命脉”与“劫持重灾区”

#### BGP劫持（前缀劫持）经典案例

- **2008年**：巴基斯坦电信误（或有意）宣告了YouTube的IP前缀（`208.65.153.0/24`），导致全球大部分YouTube流量被路由至巴基斯坦，中断数小时。
- **现代防御——RPKI/ROA（RFC 6480）** ：
  - **ROA（Route Origin Authorization）** ：IP地址所有者授权特定AS宣告特定前缀。
  - **RPKI验证**：路由器在接收BGP路由时，验证该路由的`origin AS`是否匹配ROA记录，不匹配则根据策略拒绝或降级。
  - **Cisco配置示例**：
    ```cisco
    bgp rpki server tcp 192.0.2.1 port 323 refresh 600
    bgp bestpath origin-as use rpki
    ```
  - **验证命令**：`show bgp rpki table`


## 四、高级排障与红队实战场景

### 场景1：利用ICMP重定向绕过网关（红队经典）

- **原理**：攻击者发送伪造的ICMP Type 5（Redirect）包，告诉受害者：“去往 `8.8.8.8` 不要走网关，走我这（攻击机）更快。”
- **后果**：若受害者未禁用ICMP重定向，其路由表会插入一条临时的**主机路由**（`8.8.8.8/32 via 攻击机IP`），流量被劫持。
- **防御**：
  - **Windows（Vista+默认已禁用）** ：`netsh interface ipv4 show global` 验证 `ICMP Redirects` 状态。
  - **Linux（默认允许）** ：`net.ipv4.conf.all.accept_redirects = 0`（写入`/etc/sysctl.conf`）。

### 场景2：策略路由（PBR）绕过与uRPF防御

- **PBR原理**：在路由器入接口上依据**路由映射（Route Map）** 匹配流量（如源IP），指定出接口，覆盖普通路由表的LPM决策。
- **攻击利用**：若企业配置“办公网段走出口A，服务器网段走出口B”，攻击者在办公网伪造源IP为服务器IP，发往外网，PBR将包直接扔到出口B，绕过办公网审计。
- **关键限制**：此攻击成立的前提是**未启用uRPF（严格模式）** 。若启用（`ip verify unicast source reachable-via rx`），伪造源IP的包在入接口被直接丢弃。
- **防御方案**：在启用PBR的接口上**同时开启uRPF**，阻断源IP欺骗。

### 场景3：路由环路诊断与黑洞路由排障

- **现象**：Ping/Traceroute看到TTL递减到0超时，跳数在两点间循环（A→B→A→B）。
- **根因**：路由表中存在两条互相指向对方的路由（如A认为去往X走B，B认为去往X走A）。
- **修复**：配置黑洞路由（`ip route 10.0.0.0/8 Null0`）或调整OSPF Metric打破循环。


## 五、路由攻击检测与防御纵深矩阵

| 攻击手法 | 目标协议 | 检测方法 | 防御配置 |
|:---|:---|:---|:---|
| **OSPF邻居欺骗** | OSPF | 监控异常邻居关系建立（`show ip ospf neighbor`） | OSPF SHA-256认证 + Passive-Interface |
| **LSA注入（路由劫持）** | OSPF | 监控LSA更新频率（`debug ip ospf lsa`） | 前缀列表过滤（`ip prefix-list`） |
| **BGP前缀劫持** | BGP | BGP Stream监控（前缀变化频率） | RPKI/ROA验证 + AS-Path过滤 |
| **ICMP重定向** | ICMP | 监控ICMP Type 5流量 | 终端禁用（Linux sysctl / Windows netsh） |
| **PBR绕过审计** | PBR | 监控源IP伪造（uRPF日志） | 启用uRPF严格模式 + IP Source Guard |


## 六、避坑指南（资深网工排障血泪史）

### 坑1：认为“Ping通网关”代表“路由通”
- **真相**：网关直连 ≠ 能去其他网段。必须检查 **默认网关（0.0.0.0/0）** 。若`route -n`（Linux）或`route print`（Windows）中无`0.0.0.0`的下一跳，所有非本网段包都会丢弃。

### 坑2：忽略递归路由查询（Recursive Lookup）的性能瓶颈
- 路由表中的下一跳可能是“间接地址”，需查两次表。如去往`10.0.20.0/24`的下一跳为`192.168.2.2`，路由器须再查“去往`192.168.2.2`走哪个接口”。
- 若递归条目失效，即使首条路由存在，包也出不去。**排障**：`show ip route [next-hop-ip]` 验证递归可达性。

### 坑3：混淆“路由策略”与“策略路由”
| 概念 | 层面 | 功能 |
|:---|:---|:---|
| **路由策略（Route Policy）** | 控制平面 | 影响路由表的学习和宣告（如OSPF的`route-map`过滤） |
| **策略路由（PBR）** | 数据平面 | 影响数据包的转发路径（基于源IP指定出接口） |

### 坑4：忽视前缀列表（Prefix-List）的精确匹配能力
- **ACL**：仅匹配IP地址范围，**不区分掩码长度**。
- **前缀列表（Prefix-List）** ：**同时匹配IP地址和掩码长度**（如`ge 24 le 24`精确匹配/24）。
- **攻击影响**：若目标路由器配置了`ip prefix-list DENY-PRIVATE seq 5 deny 10.0.0.0/8 ge 8 le 32`，攻击者无法注入任何`10.0.0.0/8`范围内的路由——这对红队评估路由注入可行性至关重要。


## 七、VRF（虚拟路由转发）—— 路由隔离的安全边界

- **原理**：一台物理路由器上维护多个独立路由表（VRF实例），不同VRF间路由完全隔离（类似VLAN但工作在三层）。
- **红队视角**：若拿下VRF A中的一台设备，需通过**VRF间路由泄漏（Route Leaking）** 或**VRF-aware攻击**才能横向移动至VRF B（难度极高）。
- **检测**：`show ip route vrf [name]` 查看特定VRF路由表。
- **安全价值**：VRF是实现**网络微分段**的重要技术，在多租户云环境中广泛使用。


## 八、路由安全基线检查清单

| 检查项 | 基线标准（Cisco） | 验证命令 |
|:---|:---|:---|
| 默认路由存在 | 至少一条指向出口网关的`0.0.0.0/0` | `show ip route 0.0.0.0` |
| 黑洞路由（Null0） | 关键内部网段配置防环 | `show ip route 10.0.0.0/8 \| include Null0` |
| OSPF认证 | SHA-256优先，MD5保底 | `show ip ospf interface [if] \| include authentication` |
| OSPF Passive-Interface | 终端接口启用 | `show ip ospf interface [if] \| include passive` |
| uRPF严格模式 | 边界接口启用 | `show ip verify unicast source` |
| ICMP重定向 | 终端侧禁用 | Linux：`sysctl net.ipv4.conf.all.accept_redirects` |
| BGP RPKI | 启用ROA验证 | `show bgp rpki table` |


## 九、参考资料

1. **RFC 2328** — *OSPF Version 2*（OSPFv2标准）
2. **RFC 4271** — *A Border Gateway Protocol 4 (BGP-4)*（BGP-4标准）
3. **RFC 6480** — *An Infrastructure to Support Secure Internet Routing*（RPKI基础）
4. **RFC 791** — *Internet Protocol*（IP基础）
5. **RFC 792** — *ICMP*（ICMP重定向定义）
6. **MITRE ATT&CK** — *T1557 (Adversary-in-the-Middle)*, *T1590 (Gather Victim Network Information)*
7. **Cisco Layer 3 Routing Configuration Guide**（Cisco官方三层路由配置）
8. **FRRouting Documentation**（开源路由协议栈）

---

**总结**：路由是连接整个TCP/IP协议栈的“总纲”。掌握路由，你就掌握了攻击者在**网络层做中间人**的核心技能——控制路由路径 = 控制流量走向。IP协议（寻址/分片）、ARP（下一跳MAC解析）、VLAN（二层隔离）、NAT（地址转换）均围绕路由决策协同工作。攻击者通过OSPF LSA注入实现精细化MITM，通过ICMP重定向劫持单条流量，通过BGP前缀劫持影响全球路由；防御者通过OSPF认证、uRPF、RPKI/ROA和前缀列表构建纵深防线。建议读者将本文与ARP欺骗、ICMP隧道、IP分片攻击串联，构建完整的网络层攻防知识体系。IPv6环境下的路由攻击（OSPFv3、BGPsec）将是下一个必须攻克的高地。

---

*本文修订于2026年8月，基于Ubuntu 22.04 LTS / Kali Linux 2025.1 / Cisco IOS 15.2 / FRRouting 8.5环境验证。路由协议行为因厂商及软件版本存在差异，生产环境中请以具体设备文档为准。*
