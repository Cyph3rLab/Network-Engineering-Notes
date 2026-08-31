# 路由协议深度解析：从路由表原理到OSPF/BGP攻击与内网防御实战

> **实验环境**：Ubuntu 22.04.3 LTS / Kali Linux 2025.1 / Cisco IOS 15.9(3)M / FRRouting 8.5.2 / Scapy 2.5.0
>
> **合规声明**：本文所有攻击技术描述**仅限用于网络安全防护研究与获得书面授权的隔离环境安全测试**。未经授权的OSPF LSA注入、BGP路由劫持、路由环路攻击等行为，违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条，切勿用于非法目的。


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
| **转发** | Forwarding | 数据平面 | 攻击硬件转发芯片（如CVE-2018-0171 Smart Install） |


## 二、技术原理解剖：路由表的原子结构与匹配算法

### 2.1 路由表的“基因序列”

| 字段 | 含义 | 攻防意义 |
|:---|:---|:---|
| **目标网络/掩码** | 目的地址范围 | 掩码越长优先级越高（LPM算法核心） |
| **管理距离（AD）/ Preference** | 协议可信度（越小越优） | **厂商差异极大**（见下表），注入低AD路由可覆盖合法路由 |
| **度量值（Metric）** | 到达目标的代价 | 增大合法路由Metric可引导流量走被控链路 |
| **下一跳** | 要把包发给哪个相邻IP | 下一跳被ARP欺骗，数据即被劫持 |

**管理距离（AD）/ Preference 厂商差异对照表**：

| 路由来源 | Cisco AD | 华为Preference | Juniper Preference |
|:---|:---:|:---:|:---:|
| 直连 | 0 | 0 | 0 |
| 静态 | 1 | 60（**可配置**，范围1-255） | 5 |
| eBGP | 20 | 255 | 170 |
| OSPF | 110 | **10** | 10 |
| RIP | 120 | 100 | 100 |
| iBGP | 200 | 255 | 170 |

> **⚠️ 排障关键**：跨厂商环境中，**OSPF在华为设备（Preference=10）比静态路由（Preference=60）更优**，而在Cisco中静态路由（AD=1）比OSPF（AD=110）更优。排障时必须先确认设备厂商。**华为静态路由的Preference值可配置**，生产环境中可能已被调整，排障前应通过`display current-configuration | include preference`确认实际值。

### 2.2 匹配算法：最长前缀匹配（LPM）

路由器不选最宽的，而选最精确的（掩码最长的）。路由器选择路径的完整规则为：**AD最小 → Metric最小 → LPM最长匹配**。

**安全陷阱**：若攻击者注入一条 `10.0.20.5/32`（主机路由）且其AD值**小于**合法路由（如合法路由来自OSPF AD=110，攻击者注入静态AD=1），去往该IP的流量会被送往攻击者指定的下一跳，实现**精细化MITM**。若攻击者只能注入AD=110的OSPF路由，则可能与合法路由形成ECMP（若Metric相同），仅劫持部分流量。


## 三、动态路由协议的攻防地图

### 3.1 OSPF —— 内网最常见的攻击目标

OSPF通过组播（224.0.0.5/6）发送Hello包建立邻居关系。它**默认信任邻居，且认证常被忽略**。

**OSPF邻居状态机（快速参考）** ：Down → Init → 2-Way → Exstart → Exchange → Loading → Full。攻击者需与合法路由器建立到Full邻接关系才能注入LSA。

#### 攻击手法：OSPF邻居欺骗 + LSA注入
1. 攻击者在内网拿下一台服务器，开启IP转发。
2. 伪造OSPF Hello报文，宣称自己是“骨干区域”可信路由器。
3. 若OSPF未启用认证，合法路由器会与攻击者建立Full邻接关系。
4. 攻击者发布LSA，宣称自己连接了目标网段且Metric=1。
5. **效果**：所有去往目标网段的流量被引向攻击机，实现MITM。

> **⚠️ 攻击有效性边界**：上述MITM效果仅在**目标网段的合法路由来源为OSPF（AD=110）且攻击者注入的LSA Metric小于合法Metric**时成立。若目标网段存在**静态路由（AD=1）或直连路由（AD=0）** ，OSPF LSA注入**无法覆盖**。在Cisco环境中，静态路由优先于OSPF路由。

> **⚠️ 风险提示**：LSA注入攻击需在**授权内网测试环境**中执行，注入虚假LSA可能导致全网路由震荡，影响业务。测试前准备好`clear ip ospf process`等恢复命令。

#### 防御配置（2026年生产标准）

```cisco
! 1. 优先使用HMAC-SHA-256认证
key chain OSPF-KEY
 key 1
  cryptographic-algorithm hmac-sha-256
  key-string <SECURE_PASSWORD>
!
! 2. OSPF进程配置（全局模式）
router ospf 1
 router-id 10.0.0.1
 area 0 authentication message-digest
 passive-interface default                ! ✅ 正确位置：全局配置模式
 no passive-interface GigabitEthernet0/1  ! 仅邻居接口放行
!
! 3. 接口配置（激活OSPF和TTL安全GTSM）
interface GigabitEthernet0/1
 ip ospf authentication key-chain OSPF-KEY
 ip ospf ttl-security hops 1              ! GTSM（RFC 5082），要求TTL ≥ 254，拒绝非直连邻居
 ip ospf 1 area 0
```

> **配置说明**：
> - `passive-interface default`是**全局配置命令**（在`router ospf`下），**不能**放在接口配置块中；
> - `ip ospf ttl-security hops 1` — 要求接收的OSPF包TTL ≥ (255 - hops) = 254，**拒绝非直连邻居（TTL < 254）的OSPF报文**；
> - 若邻居间MTU不一致，OSPF邻居可能卡在ExStart状态，可用`ip ospf mtu-ignore`解决（仅限测试环境）。

**验证命令**：`show ip ospf neighbor`、`show ip ospf interface`（确认认证和GTSM生效）。

### 3.2 BGP —— 互联网的“命脉”与“劫持重灾区”

**现代防御——RPKI/ROA（RFC 6480）**：
- **ROA**：IP地址所有者授权特定AS宣告特定前缀。
- **RPKI验证**：路由器在接收BGP路由时，验证`origin AS`是否匹配ROA记录，不匹配则拒绝。

**⚠️ RPKI的局限性**：RPKI仅验证**源AS**合法性，不验证**路径**合法性。攻击者若在AS_PATH中插入合法源AS但篡改中间AS路径，仍可能绕过RPKI检测。BGPsec（RFC 8205）提供了路径验证能力，但部署率极低。

**Cisco IOS XE配置示例**：
```cisco
router bgp <AS_NUMBER>
 bgp rpki server tcp 192.0.2.1 port 323 refresh 600
 bgp bestpath origin-as use rpki        ! IOS XE 16.12.1+ 语法
 ! IOS XE 16.12之前版本使用: bgp bestpath origin-as validate
```

**验证命令**：`show bgp rpki table` 查看ROA验证状态。


## 四、红队攻击场景：路由劫持实战

### 4.1 利用ICMP重定向绕过网关（主机侧路由劫持）

> ⚠️ **注意**：现代Windows Vista+和较新Linux内核默认已禁用ICMP重定向接收，此攻击**仅在特定老旧设备或未加固终端上有效**。

- **原理**：攻击者发送伪造的ICMP Type 5，告诉受害者“去往目标走我这更快”。受害者路由表插入临时主机路由，流量被劫持。
- **防御（终端侧，完整接收+发送）** ：
  ```bash
  # Linux：禁用接收和发送ICMP重定向
  sysctl -w net.ipv4.conf.all.accept_redirects=0
  sysctl -w net.ipv4.conf.all.send_redirects=0      # 防止本机被用作重定向攻击跳板
  ```
  **Windows注册表**：`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect` = 0（禁用接收），发送重定向在Windows中默认不开启。

### 4.2 策略路由（PBR）绕过

- **PBR原理**：在入接口依据源IP指定出接口，覆盖普通路由表。
- **攻击利用**：在办公网伪造源IP为服务器IP，PBR将包扔到服务器出口，绕过办公网审计。
- **防御方案**：在启用PBR的接口上**同时开启uRPF严格模式**（`ip verify unicast source reachable-via rx`），伪造源IP的包在入接口被直接丢弃。


## 五、避坑指南（资深网工排障血泪史）

### 坑1：认为“Ping通网关”代表“路由通”
网关直连 ≠ 能去其他网段。必须检查默认网关（`0.0.0.0/0`）是否存在。

### 坑2：忽略递归路由查询的性能瓶颈
下一跳若是间接地址，需查两次表。若递归条目失效，首条路由存在包也出不去。排障：`show ip route [next-hop-ip]`验证递归可达性。

### 坑3：混淆“路由策略”与“策略路由”

| 概念 | 层面 | 功能 |
|:---|:---|:---|
| **路由策略** | 控制平面 | 影响路由表的学习和宣告（如Route-Map、Distribute-List） |
| **策略路由（PBR）** | 数据平面 | 影响数据包的转发路径（如Route-Map + set ip next-hop） |

### 坑4：忽视前缀列表的精确匹配能力

- **ACL**：仅匹配IP地址范围，不区分掩码长度。
- **前缀列表**：同时匹配IP地址和掩码长度。

**正确用法（Cisco）** ：

```cisco
! 1. 拒绝所有10.0.0.0/8的子网路由（含/8本身）
ip prefix-list DENY-PRIVATE seq 5 deny 10.0.0.0/8 le 32

! 2. 若仅拒绝/8本身，放行其子网（如10.1.0.0/16）
ip prefix-list DENY-ONLY-8 seq 5 deny 10.0.0.0/8 ge 9

! 3. 若仅匹配特定长度范围（例如/16-/24）
ip prefix-list MATCH-RANGE seq 5 permit 10.0.0.0/8 ge 16 le 24
```


## 六、VRF（虚拟路由转发）—— 路由隔离的安全边界

- **原理**：一台物理路由器上维护多个独立路由表，不同VRF间路由**默认隔离**。
- **安全提醒**：VRF间可通过**路由泄漏（Route Leaking）** 或VRF间静态路由实现互通。在生产环境中，路由泄漏是常见运维需求（如管理VRF访问业务VRF），需使用独立route-map精确控制泄漏范围，避免将敏感路由意外泄露到不安全VRF。
- **VRF路由泄漏的工程实现与安全风险**：
  - **静态泄漏**：`ip route vrf A 10.0.0.0/24 vrf B 192.168.1.1`——将VRF A中的路由泄漏到VRF B，**需注意避免双向泄漏导致路由环路**；
  - **MP-BGP泄漏**：通过`route-target export/import`控制VRF间的路由交换，**需严格审计Route-Target配置**，避免过度泄漏；
  - **安全基线**：泄漏时应使用`route-map`精确过滤，仅泄漏必要路由（如`deny`敏感管理网段）。
- **红队视角**：若拿下VRF A中的设备，需通过VRF间路由泄漏配置漏洞才能横向移动至VRF B，难度较高。
- **安全价值**：VRF结合MPLS是实现数据中心多租户隔离与网络微分段的核心技术。


## 七、路由安全基线检查清单

| 检查项 | 基线标准（Cisco） | 验证命令 |
|:---|:---|:---|
| OSPF认证 | HMAC-SHA-256优先 | `show ip ospf interface` |
| OSPF TTL安全（GTSM） | 直连邻居间启用 | `show ip ospf interface` |
| uRPF严格模式 | 边界接口启用 | `show ip verify unicast source` |
| BGP RPKI | 启用ROA验证 | `show bgp rpki table` |
| ICMP重定向禁用 | 终端侧`accept_redirects=0`、`send_redirects=0` | `sysctl net.ipv4.conf.all.accept_redirects` |


## 八、进阶延伸：OSPF排障快速决策树

```text
OSPF邻居未建立
 ├── show ip ospf neighbor 检查状态
 ├── 卡在 INIT/DOWN
 │   ├── Hello包未到达 → 检查防火墙是否放行组播224.0.0.5/6
 │   ├── 区域ID不匹配 → 检查 area 配置
 │   └── 网络类型不匹配（广播 vs 点对点）→ ip ospf network
 ├── 卡在 EXSTART/EXCHANGE
 │   └── MTU不一致 → ip ospf mtu-ignore（测试用）或统一MTU
 ├── 卡在 2WAY
 │   ├── 区域ID不匹配 → 核对两端区域号
 │   └── 路由器ID冲突 → router-id 唯一性检查
 └── 卡在 LOADING
     └── LSA数据库同步异常 → debug ip ospf lsa（慎用）
```


## 九、参考资料

1. **RFC 2328** — *OSPF Version 2*（1998），J. Moy
2. **RFC 4271** — *A Border Gateway Protocol 4 (BGP-4)*（2006），Y. Rekhter et al.
3. **RFC 5082** — *The Generalized TTL Security Mechanism (GTSM)*（2007），V. Gill et al.
4. **RFC 6480** — *An Infrastructure to Support Secure Internet Routing*（RPKI基础，2012）
5. **RFC 8205** — *BGPsec Protocol Specification*（2017），M. Lepinski, K. Sriram
6. **MITRE ATT&CK** — [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)，[T1596.005: Search Open Technical Databases (BGP)](https://attack.mitre.org/techniques/T1596/005/)


**总结**：路由是连接整个TCP/IP协议栈的“总纲”。掌握路由，你就掌握了攻击者在网络层做中间人的核心技能。攻击者通过OSPF LSA注入实现精细化MITM（需AD值低于合法路由），通过ICMP重定向劫持单条流量（仅限老旧终端）；防御者必须通过OSPF SHA-256认证、GTSM（TTL安全）、uRPF和RPKI构建纵深防线。**跨厂商环境中，务必注意AD/Preference值的差异**（华为OSPF=10，Cisco OSPF=110），这是排障和攻击路径评估的关键前提。建议读者将本文与ARP欺骗、ICMP隧道串联，构建完整的网络层攻防知识体系。

---

*本文修订于2026年8月，基于Ubuntu 22.04.3 LTS / Cisco IOS 15.9(3)M环境验证。路由协议行为因厂商及软件版本存在差异，生产环境中请以具体设备官方文档为准。*
