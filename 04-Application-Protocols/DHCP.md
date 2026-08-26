# DHCP协议深度解析：从DORA流程到内网渗透入口攻击实战

> **实验环境**：Ubuntu 22.04.3 LTS / Windows 11 22H2 / Kali Linux 2025.1 / Cisco IOS 15.9(3)M（Catalyst 3850模拟）/ Wireshark 4.2.6 / yersinia 0.7.3-1
>
> **合规声明**：本文所有攻击技术描述**仅限用于网络安全防护研究与获得书面授权的隔离环境安全测试**。未经授权的DHCP饥饿攻击、Rogue DHCP部署、IP地址耗尽等行为，违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条，切勿用于非法目的。


## 一、内网攻击链中的DHCP定位（总纲）

DHCP是内网攻击链的**第一环**——控制DHCP，就控制了“身份的源头”。理解DHCP攻防，是掌握内网渗透入口技术的第一步，也是构建完整网络层防御体系的起点。


## 二、DHCP是什么？

**DHCP**全称：Dynamic Host Configuration Protocol（动态主机配置协议，RFC 2131，1997年）。
**作用**：自动给客户端分配网络配置参数（IP地址、子网掩码、默认网关、DNS服务器等）。
**层级**：应用层，基于UDP传输（Server端口=67，Client端口=68）。

> **排障盲区**：当DHCP服务器不可用时，Windows主机将自动分配**APIPA地址（169.254.x.x/16，RFC 3927）** 。看到169.254.x.x即提示DHCP服务故障，应优先检查DHCP Server状态和网络连通性。


## 三、DHCP角色与跨VLAN转发

| 角色 | 说明 | 典型设备 |
|:---|:---|:---|
| **DHCP Client** | 请求IP配置 | PC、手机、服务器 |
| **DHCP Server** | 分配IP、管理地址池 | 路由器、Windows Server、ISC DHCPd |
| **DHCP Relay** | 跨VLAN转发DHCP广播 | 三层交换机、路由器 |

DHCP Discover是广播帧，无法跨越VLAN边界。解决方案是配置**DHCP Relay**（`ip helper-address`）。

**`ip helper-address`默认转发的8种UDP广播协议（Cisco）** ：

| 协议 | 端口 | 是否需要跨VLAN转发 |
|:---|:---:|:---|
| DHCP/BOOTP | 67/68 | ✅ 必须 |
| TFTP | 69 | 按需 |
| DNS | 53 | 按需 |
| Time | 37 | 极少 |
| TACACS | 49 | 极少 |
| NetBIOS Name Service | 137 | ⚠️ 高风险（易产生广播扩散） |
| NetBIOS Datagram | 138 | ⚠️ 高风险（易产生广播扩散） |

> **⚠️ 跨VLAN转发NetBIOS的风险与精确控制**：转发NetBIOS（UDP 137/138）会增加跨VLAN广播流量。若源VLAN内存在大量Windows主机且未禁用NetBIOS over TCP/IP，广播流量将被扩散到其他VLAN，增加跨VLAN带宽负担和CPU负载。生产环境中，若无需跨VLAN NetBIOS解析，应使用`no ip forward-protocol udp 137`和`no ip forward-protocol udp 138`精确关闭NetBIOS转发。


## 四、DORA流程详解（附Option 54关键细节）

DORA是DHCP最重要的概念：**Discover → Offer → Request → Acknowledge**。

1. **DHCP Discover（广播）** ：客户端广播寻找DHCP服务器。若设置了Broadcast标志位（现代OS默认设置），告知服务器必须以广播回复。
2. **DHCP Offer（广播/单播）** ：服务器回复可用配置。通常因Discover携带Broadcast=1，故为广播。
3. **DHCP Request（关键细节——Option 54）** ：客户端广播（首次获取）或单播（续租阶段）发出Request。**Option 54（Server Identifier）** 明确填写所选服务器的IP地址。未被选中的服务器看到Option 54不是自己，立即撤销预留的IP。
4. **DHCP ACK**：服务器确认配置生效。


## 五、DHCP报文结构（攻防视角）

核心字段及其攻防意义：

| 字段 | 说明 | 攻防意义 |
|:---|:---|:---|
| **`giaddr`（中继代理IP）** | DHCP Relay填入的网关地址 | 攻击者若伪造此字段，可绕过基于源IP的DHCP Server访问控制 |
| **`chaddr`（客户端硬件地址）** | 客户端MAC地址 | Starvation攻击中可伪造该字段，但**需注意**：要填满CAM表，必须同时伪造以太网帧源MAC |
| **Option 54** | Server Identifier | Rogue DHCP攻击中，客户端通过此字段声明所选服务器 |
| **Option 55/60** | 参数请求列表 / 厂商标识 | 可用于操作系统指纹识别（红队侦察） |
| **Option 82（RFC 3046）** | Relay Agent Information（含Circuit ID和Remote ID） | 用于DHCP Snooping精确定位客户端接入端口 |


## 六、攻击手法详解（内网渗透入口）

> **⚠️ 严重风险警示**：以下攻击技术会导致大面积断网或流量劫持，**严禁在生产环境或未授权环境中模拟**。实验须在完全隔离的虚拟网络中进行。

### 6.1 DHCP Starvation（饥饿攻击）与CAM表溢出的联动

- **原理**：攻击者发送大量伪造的DHCP Discover请求，耗尽DHCP Server地址池。
- **CAM表溢出的触发条件（关键前提）** ：
  - 若攻击工具**同时伪造了以太网帧的源MAC地址**（而非仅伪造DHCP报文中的`chaddr`字段），则交换机CAM表会学习到海量伪造MAC，导致CAM表溢出（退化为Hub），未知单播流量泛洪，攻击者可借此被动嗅探同VLAN流量。
  - 若工具仅伪造`chaddr`但保持以太网帧源MAC为真实攻击者MAC，则CAM表不受影响。
- **实战状态**：主流攻击工具（如`yersinia`）的DHCP Starvation功能**默认会伪造以太网帧源MAC**，因此CAM表溢出是常见副作用。

**防御**：Port Security限制单端口MAC数量 + DHCP Snooping限速。

### 6.2 Starvation + Rogue DHCP Server（红队核心组合攻击）

攻击者先耗尽合法服务器地址池，使新客户端无法获取IP。随后部署Rogue DHCP Server响应请求。因合法服务器无竞争，客户端被迫接受恶意配置（如被分配攻击者IP作为网关/DNS），实现隐蔽MITM。

### 6.3 DHCP Release伪造攻击（踢人下线）

- **原理**：伪造目标MAC地址发送DHCP Release报文。
- **平台差异**：Windows DHCP Server收到Release后立即回收IP；ISC DHCPd（Linux）默认忽略Release。
- **红队价值**：针对VIP主机精确打击，比全局DoS更隐蔽。

### 6.4 IPv6盲区——SLAAC/RA伪造攻击（非DHCPv6）

- **协议澄清**：该攻击利用IPv6无状态地址自动配置（SLAAC，RFC 4861）中的RA（Router Advertisement）机制，**属于ICMPv6范畴，而非DHCPv6协议**。
- **攻击原理**：攻击者发送伪造的ICMPv6 RA，宣称自己的链路本地地址为默认网关。可通过两种方式诱导客户端：
  - **方式一**：设置`Router Lifetime`为较大值（如9000秒），使客户端长期将攻击者视为默认网关；
  - **方式二**：发送`Router Lifetime = 0`的RA撤销合法网关（需结合攻击者自身的RA进行覆盖）。
  `Default Router Preference`（RFC 4191可选字段）可辅助提高攻击者路由的优先级，但**并非所有客户端都支持**，不应作为唯一手段。
- **防御**：启用**IPv6 RA Guard**（`ipv6 nd raguard`）。


## 七、DHCP防御纵深

### 7.1 DHCP Snooping（企业网基石）

交换机监听DHCP流量，建立合法绑定表（`IP | MAC | 端口 | VLAN | 租期`）。
- **信任端口**：连接合法DHCP Server的上联端口。
- **非信任端口**：客户端端口。收到Offer/Acknowledge直接丢弃。

> **⚠️ 配置避坑**：配置Snooping时，交换机互联的Trunk口通常需设为Trust，否则跨交换机的DHCP Offer会被错误丢弃。

**Option 82与DHCP Snooping的联动（跨VLAN场景）** ：
当DHCP Relay转发Discover时，会插入Option 82（RFC 3046），包含`Circuit ID`（接入端口标识）和`Remote ID`（交换机标识）。DHCP Snooping结合Option 82可精确定位DHCP请求来源，防止攻击者在同一交换机不同端口间伪造MAC地址。
```cisco
ip dhcp snooping information option
ip dhcp snooping vlan 10,20
```

### 7.2 限速与端口安全

非信任端口配置DHCP报文速率上限（如10 pps）并限制MAC数量，从源头阻止Starvation填满绑定表或CAM表。

### 7.3 DAI（Dynamic ARP Inspection）与IPSG（IP Source Guard）

- **DAI**：结合DHCP Snooping绑定表，校验ARP报文的IP/MAC合法性，阻止Rogue Server下发的恶意网关ARP解析。
- **IPSG**：在交换机端口上仅允许绑定表中的IP+MAC组合通过，阻断Rogue DHCP Server分配的错误IP在终端上的使用。

> **⚠️ 绕过DHCP Snooping的对抗（关键区别）** ：当绑定表被Starvation填满时，不同厂商设备行为不同——
> - **Cisco Catalyst**：默认**fail-close**（新DHCP请求被丢弃）；
> - **华为S系列（部分型号）** ：默认**fail-open**（允许新DHCP请求通过，需显式配置`dhcp snooping user-bind max-number`限制绑定表大小）。
> 
> 因此，**限速配置是绝对前提**，不应依赖设备默认行为。


## 八、DHCP协议安全基线检查清单

| 检查项 | 基线标准 | 验证命令（Cisco） |
|:---|:---|:---|
| DHCP Snooping | 全局及VLAN启用 | `show ip dhcp snooping` |
| DHCP Snooping限速 | 非信任端口≤10 pps | `show ip dhcp snooping interface Gi0/1` |
| Port Security | 接入端口MAC≤2 | `show port-security interface Gi0/1` |
| DAI联动 | 绑定表存在且一致 | `show ip dhcp snooping binding` |
| IPSG启用 | 接入端口启用IP+MAC校验 | `show ip verify source interface Gi0/1` |
| IPv6 RA Guard | 启用（如需IPv6） | `show ipv6 nd raguard` |
| Relay精确控制 | 移除UDP 137/138转发 | `show run \| include forward-protocol` |
| 绑定表容量 | 显式配置上限，避免fail-open | `ip dhcp snooping binding max-number` |


## 九、实战抓包分析（Wireshark）

```bash
# 抓取所有DHCP流量
tcpdump -i eth0 -nn 'udp port 67 or udp port 68' -w dhcp.pcap
```

**异常检测指标**：
- 单源MAC发出海量Discover → 疑似Starvation攻击。
- 非授权IP发出Offer/ACK → 疑似Rogue DHCP Server。
- 异常Option 54值 → 疑似欺骗（客户端选择了非预期服务器）。


## 十、总结

控制DHCP = 控制“身份的源头”。理解DORA流程、Option 54细节、Starvation与Rogue组合攻击、IPv6 SLAAC/RA盲区，是内网渗透入门的第一步。

**关键澄清**：
- **Starvation导致CAM表溢出需同时伪造以太网帧源MAC**（而非仅伪造DHCP `chaddr`），两者是不同协议层的操作；
- **`ip helper-address`转发NetBIOS的风险**取决于源VLAN内NetBIOS流量大小，需精确控制`no ip forward-protocol`而非一刀切；
- **IPv6 RA欺骗**的核心机制是RA中的`Router Lifetime`字段，`Default Router Preference`为可选扩展，非所有客户端支持。

防御方需部署**DHCP Snooping + 限速 + Port Security + DAI + IPSG**的五层组合，并务必检查IPv6安全策略是否为空白（RA Guard）。下一步，建议将DHCP与ARP欺骗、DNS劫持串联，构建完整的网络层与应用层联动防御视角。


## 参考资料

1. **RFC 2131** — *Dynamic Host Configuration Protocol*（DHCPv4标准，1997）
2. **RFC 3046** — *DHCP Relay Agent Information Option*（Option 82标准，2001）
3. **RFC 3315** — *Dynamic Host Configuration Protocol for IPv6 (DHCPv6)*（2003）
4. **RFC 4861** — *Neighbor Discovery for IPv6*（SLAAC/RA机制，2007）
5. **RFC 4191** — *Default Router Preferences and More-Specific Routes*（RA Preference扩展，2005）
6. **Cisco Catalyst DHCP Snooping Configuration Guide**, IOS XE 16.x
7. **MITRE ATT&CK** — [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)


*本文修订于2026年8月，基于Ubuntu 22.04.3 LTS / Cisco IOS 15.9(3)M环境验证。DHCP行为因操作系统及厂商实现存在差异，生产环境中请以具体设备文档为准。*
