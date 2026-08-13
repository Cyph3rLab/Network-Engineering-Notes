# DHCP协议深度解析：从DORA流程到内网渗透入口攻击实战

> **实验环境**：Ubuntu 22.04 LTS / Windows 11 22H2 / Kali Linux 2025.1 / Cisco IOS 15.2（模拟器）/ Wireshark 4.2.6 / yersinia 0.7.3
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。


## 零、内网攻击链中的DHCP定位（总纲）

```text
客户端上线
    ↓
DHCP（我要网络身份）          ← 【本篇 · 攻击链第一环】
    ↓
ARP（IP找MAC）               ← 已学
    ↓
DNS（域名找IP）              ← 待学
    ↓
LLMNR/NBT-NS（局域网名字解析） ← UDP 137/5353
    ↓
认证协议（NTLM/Kerberos）     ← 待学
    ↓
横向移动                     ← 终极目标
```

DHCP是这条攻击链的**第一环**——控制DHCP，就控制了“身份的源头”。掌握DHCP攻防，是理解内网渗透入口的第一步。


## 一、DHCP是什么？

**DHCP**全称：Dynamic Host Configuration Protocol（动态主机配置协议，RFC 2131）。

**作用**：自动给客户端分配网络配置参数：
- IP地址、子网掩码、默认网关（Option 3）
- DNS服务器（Option 6）
- 租期（Lease Time，Option 51）
- 域名信息（Option 15）
- 其他自定义选项

**场景**：电脑刚连接WiFi时，IP/网关/DNS均为未知。发送DHCP请求后，服务器回复配置，即刻可上网。


## 二、为什么需要DHCP？

无DHCP时代，管理员需手动配置每台设备的IP/掩码/网关/DNS。大规模网络（1000+终端）配置成本极高，IP冲突频发。DHCP实现了网络配置的**自动化与集中管理**。

> **排障盲区**：当DHCP服务器不可用时，Windows主机会自动分配**APIPA地址（169.254.x.x/16，RFC 3927）** ，仅能用于同一子网通信，无法访问网关。看到169.254.x.x即提示DHCP服务故障。


## 三、DHCP工作在哪一层？

DHCP工作在**应用层**（使用UDP传输），端口：**UDP 67（服务器）**、**UDP 68（客户端）**。

> 记忆口诀：**Server=67，Client=68**


## 四、DHCP的角色与协议结构

| 角色 | 说明 | 典型设备 |
| :--- | :--- | :--- |
| **DHCP Client** | 请求IP配置 | PC、手机、Linux主机 |
| **DHCP Server** | 分配IP、管理地址池 | 路由器、Windows DHCP Server、ISC DHCPd |
| **DHCP Relay** | 跨VLAN转发DHCP广播 | 三层交换机、路由器 |

### VLAN环境下的DHCP行为

DHCP Discover是广播帧，**无法跨越VLAN边界**。解决方案：

- 每个VLAN部署独立DHCP Server（成本高）
- 配置**DHCP Relay**（`ip helper-address`），将广播转为单播转发给中央DHCP Server。

**Cisco配置示例**：
```cisco
interface vlan 10
  ip helper-address 192.168.100.10
```

> **⚠️ 踩坑警告**：`ip helper-address`不仅转发DHCP，还会转发**TFTP、DNS、NetBIOS等7种UDP广播**。可用`ip forward-protocol udp`精确控制转发的协议类型，避免非必要广播放大。


## 五、DORA流程详解（附Option 54关键细节）

DORA是DHCP最重要的概念：

- **D** = Discover（发现）
- **O** = Offer（提供）
- **R** = Request（请求）
- **A** = Acknowledge（确认）

### 1. DHCP Discover（广播）

客户端上线，广播寻找DHCP服务器：
- 目标MAC：`FF:FF:FF:FF:FF:FF`
- 目标IP：`255.255.255.255`
- 内容：携带Client MAC地址（`chaddr`字段）和Option 55（Parameter Request List，请求参数列表）

> 类比：「谁能给我一个地址？」

### 2. DHCP Offer（单播/广播，取决于flags）

DHCP服务器回复可用配置：
- IP地址、掩码、网关、DNS、租期（86400秒）
- 若有多个Offer，客户端选择最先到达或最优的。

### 3. DHCP Request（关键细节——Option 54 Server Identifier）

客户端广播（**首次获取**）或单播（**续租阶段**）发出Request：

- 广播内容：「我要192.168.1.50，我选择A服务器」
- **⚠️ Option 54（Server Identifier）** ：客户端**明确填写所选服务器的IP地址**。
  - 被选中的服务器 → 准备发送ACK。
  - 未被选中的服务器 → 看到Option 54不是自己，**撤销之前预留的IP**，释放资源。
- **续租阶段（T1/T2）** ：Request为**单播**直接发给原服务器，非广播。

### 4. DHCP ACK

服务器确认：「192.168.1.50给你，有效期8小时」。客户端配置完成。


## 六、DHCP报文结构（攻防视角）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op(1)     |   htype(1)   |   hlen(1)    |   hops(1)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             xid(4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          secs(2)             |           flags(2)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          ciaddr(4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          yiaddr(4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          siaddr(4)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          giaddr(4)       ← 攻击者关注！      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          chaddr(16)        ← 客户端MAC       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          sname(64)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          file(128)                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          options(可变)                       |
|              (Option 53: Message Type, Option 54: Server ID)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| 字段 | 攻击价值 |
| :--- | :--- |
| **`giaddr`（中继代理IP）** | 攻击者若伪造此字段，可绕过基于源IP的DHCP Server访问控制 |
| **`chaddr`（客户端MAC）** | Starvation攻击的核心——伪造不同MAC填满地址池 |
| **Option 54** | Rogue DHCP攻击中，客户端通过此字段声明所选服务器 |
| **Option 55** | 客户端请求的参数列表，可用于**指纹识别**（不同OS请求的Option不同） |
| **Option 60（Vendor Class）** | 标识客户端类型（如Windows/Linux/iPhone），可伪造绕过策略 |


## 七、DHCP租约机制

- **T1（50%租期）**：客户端尝试续租（单播Request）→ 收到ACK则续租成功。
- **T2（87.5%租期）**：若T1失败，再次续租（广播，因可能已跨子网）。
- **租期到期**：若均失败，IP被收回，重新Discover。


## 八、DHCP与ARP/LLMNR欺骗的区别（协议层对比）

| 攻击 | 攻击层次 | 控制内容 | 发生时机 |
| :--- | :--- | :--- | :--- |
| **ARP欺骗** | 二层（数据链路层） | IP→MAC映射 | 已联网后 |
| **DHCP欺骗** | 应用层（UDP） | 网络配置分配过程 | 客户端获取配置时 |
| **DNS劫持** | 应用层（UDP/TCP 53） | 域名→IP解析 | DNS查询时 |
| **LLMNR投毒** | 应用层（UDP 5355） | 名称解析 | 名称解析回退时 |


## 九、攻击手法详解（内网渗透入口）

### 1. DHCP Starvation（饥饿攻击）

- **原理**：伪造海量不同MAC地址的Discover请求，耗尽DHCP Server地址池（如100个IP耗尽）。
- **工具**：`yersinia`、`dhcpstarv`、Metasploit `auxiliary/dos/dhcp/dhcp_dos`
- **效果**：正常用户无法获取IP，网络中断（DoS）。
- **额外影响**：大量DHCP包可**耗尽交换机CPU**（控制平面需处理每个DHCP包并写入绑定表）。

### 2. Starvation + Rogue DHCP Server（红队核心组合攻击）

1. 攻击者发起**Starvation**，耗尽合法DHCP Server地址池。
2. 合法服务器无IP可分配后，新上线客户端无法获取IP。
3. 攻击者部署**Rogue DHCP Server**，响应Discover请求。
4. 因合法服务器无竞争（地址池空），客户端**被迫接受恶意配置**。

> **效果**：比单纯Rogue DHCP更隐蔽——用户看到“拿到了IP”，仅抱怨“网络慢”，而非彻底断网。

### 3. DHCP Release伪造攻击（踢人下线——Windows环境有效）

- **原理**：攻击者伪造目标MAC地址，发送DHCP Release报文。
- **平台差异**：**Windows DHCP Server**收到Release后**立即回收IP**；**ISC DHCPd（Linux）** 默认**忽略Release**（除非配置`release-on-unknown`）。
- **后果**：目标主机断网。
- **红队价值**：针对VIP主机（域控、核心数据库）精确打击，比全局DoS更隐蔽。

### 4. IPv6盲区——伪造RA（Router Advertisement）劫持IPv6流量

- **原理**：攻击者发送伪造的ICMPv6 RA，携带：
  - `Prefix Information Option`——宣告IPv6前缀，使客户端自动生成地址（SLAAC）。
  - `Default Router Preference = High`——引导客户端将默认网关指向攻击者。
- **前提**：客户端启用IPv6且SLAAC优先（Windows默认；Linux部分发行版默认）。
- **后果**：所有IPv6流量被劫持，**完全绕过IPv4的DHCP Snooping、DAI、防火墙策略**。
- **防御**：启用**IPv6 RA Guard**（Cisco：`ipv6 nd raguard`）。

### 5. DHCP Option 82伪造（高阶）

- Option 82由DHCP Relay插入，包含客户端接入端口和VLAN信息。
- 攻击者若控制Relay设备，可伪造Option 82，使DHCP Server将客户端“伪装”成来自不同端口，获取非法IP。
- **防御**：DHCP Server配置`ignore option 82`或启用校验。


## 十、DHCP防御纵深

### 1. DHCP Snooping（企业网基石）

**原理**：交换机监听DHCP流量，建立合法绑定表（`IP | MAC | 端口 | VLAN | 租期`）。
- **信任端口（Trusted）** ：连接合法DHCP Server的端口。
- **非信任端口（Untrusted）** ：客户端端口。若非信任端口收到Offer/Acknowledge，**直接丢弃**。

**Cisco配置示例**：
```cisco
ip dhcp snooping
ip dhcp snooping vlan 10,20,30
interface GigabitEthernet0/1
  ip dhcp snooping trust          ! 上联端口
interface GigabitEthernet0/2
  ip dhcp snooping limit rate 10  ! 限速，防Starvation
```

> **⚠️ DHCP Snooping是DAI（动态ARP检测）的数据来源基石**：无绑定表，DAI无法校验ARP真实性。

### 2. Port Security

限制单端口MAC学习数量（如1-2个），阻断Starvation的伪造MAC。

### 3. DHCP Snooping限速（防绕过 + 防CPU耗尽）

每个非信任端口配置DHCP报文速率上限（如10 pps），防止攻击者高频请求填满绑定表或耗尽交换机CPU。

### 4. DAI（Dynamic ARP Inspection）

结合DHCP Snooping绑定表，校验ARP报文的IP/MAC合法性，不一致则丢弃。

### ⚠️ 绕过DHCP Snooping的盲区与对抗

- **盲区**：攻击者发起Starvation填满绑定表后，**部分中低端交换机**进入降级模式（fail-open），放行所有DHCP。
- **厂商差异**：**Cisco Catalyst**默认fail-close（丢弃新DHCP）；**部分H3C/华为低端**可能fail-open。
- **对抗**：配置**端口限速** + **Port Security**，从源头阻止绑定表被填满。

### 5. DHCP指纹识别（Option 55/60）

通过Option 55（请求参数列表）和Option 60（Vendor Class）识别客户端类型，阻断非法设备接入。


## 十一、DHCP协议安全基线检查清单

| 检查项 | 基线标准 | 验证命令（Cisco） |
|:---|:---|:---|
| DHCP Snooping | 全局启用 | `show ip dhcp snooping` |
| DHCP Snooping限速 | 非信任端口≤10 pps | `show ip dhcp snooping interface Gi0/1` |
| Port Security | 接入端口MAC≤2 | `show port-security interface Gi0/1` |
| DAI联动 | 绑定表存在且一致 | `show ip dhcp snooping binding` |
| DHCP Server ACL | 仅允许授权Server的UDP 67 | 防火墙规则 |
| IPv6 RA Guard | 启用（如需要IPv6） | `show ipv6 nd raguard` |


## 十二、实战抓包分析（Wireshark）

**捕获过滤器**：
```bash
# 抓取所有DHCP流量
tcpdump -i eth0 -nn 'udp port 67 or udp port 68' -w dhcp.pcap
```

**Wireshark显示过滤器**：

| 场景 | 过滤器 |
| :--- | :--- |
| 所有DHCP报文 | `dhcp` |
| Discover报文 | `dhcp.option.dhcp == 1` |
| Offer报文 | `dhcp.option.dhcp == 2` |
| Request报文 | `dhcp.option.dhcp == 3` |
| ACK报文 | `dhcp.option.dhcp == 5` |
| 查看Option 54（Server ID） | `dhcp.option.sid` |
| 查看Option 55（请求参数列表） | `dhcp.option.param_req_list` |

**异常检测**：
- 单源MAC发出海量Discover → 疑似Starvation。
- 非授权IP发出Offer/ACK → 疑似Rogue DHCP Server。
- 异常Option 54值 → 疑似欺骗。


## 十三、总结：内网攻击链的第一环

```text
客户端上线
    ↓
DHCP（我要网络身份）          ← 本篇 · 攻击链起点
    ↓
ARP（IP找MAC）               ← 已学
    ↓
DNS（域名找IP）              ← 待学
    ↓
LLMNR/NBT-NS（局域网名字解析） ← UDP 137/5353
    ↓
认证协议（NTLM/Kerberos）     ← 待学
    ↓
横向移动                     ← 终极目标
```

控制DHCP = 控制“身份的源头”。理解DORA流程、Option 54细节、Starvation+Rogue组合攻击、Release伪造（Windows环境）、IPv6 RA劫持盲区，是内网渗透入门的第一步。防御方需部署DHCP Snooping + DAI + Port Security + 限速的四层组合，并**务必检查IPv6安全策略是否为空白**。


## 十四、参考资料

1. **RFC 2131** — *Dynamic Host Configuration Protocol*（DHCPv4标准）
2. **RFC 3315** — *Dynamic Host Configuration Protocol for IPv6 (DHCPv6)*
3. **RFC 3927** — *Dynamic Configuration of IPv4 Link-Local Addresses*（APIPA）
4. **RFC 4861** — *Neighbor Discovery for IPv6*（SLAAC/RA）
5. **RFC 3046** — *DHCP Relay Agent Information Option*（Option 82）
6. **Cisco DHCP Snooping Configuration Guide**
7. **MITRE ATT&CK** — *T1046 (Network Service Scanning)*

---

*本文修订于2026年8月，基于Ubuntu 22.04 LTS / Kali Linux 2025.1 / Windows 11 22H2 / Cisco IOS 15.2 / Wireshark 4.2.6环境验证。DHCP行为因操作系统及厂商实现存在差异，生产环境中请以具体设备文档为准。*
