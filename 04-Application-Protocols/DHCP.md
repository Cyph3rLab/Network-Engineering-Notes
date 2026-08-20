# DHCP协议深度解析：从DORA流程到内网渗透入口攻击实战

> **实验环境**：Ubuntu 22.04 LTS / Windows 11 22H2 / Kali Linux 2025.1 / Cisco IOS 15.2（模拟器）/ Wireshark 4.2.6 / yersinia 0.7.3
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。

## 一、内网攻击链中的DHCP定位（总纲）

DHCP是内网攻击链的**第一环**——控制DHCP，就控制了“身份的源头”。掌握DHCP攻防，是理解内网渗透入口的第一步。

## 二、DHCP是什么？

**DHCP**全称：Dynamic Host Configuration Protocol（动态主机配置协议，RFC 2131）。
**作用**：自动给客户端分配网络配置参数（IP地址、掩码、网关、DNS等）。
**层级**：应用层，基于UDP传输（Server=67，Client=68）。

> **排障盲区**：当DHCP服务器不可用时，Windows主机会自动分配**APIPA地址（169.254.x.x/16，RFC 3927）**。看到169.254.x.x即提示DHCP服务故障。

## 三、DHCP角色与跨VLAN转发

| 角色 | 说明 | 典型设备 |
| :--- | :--- | :--- |
| **DHCP Client** | 请求IP配置 | PC、手机、服务器 |
| **DHCP Server** | 分配IP、管理地址池 | 路由器、Windows Server、ISC DHCPd |
| **DHCP Relay** | 跨VLAN转发DHCP广播 | 三层交换机、路由器 |

DHCP Discover是广播帧，无法跨越VLAN边界。解决方案是配置**DHCP Relay**（`ip helper-address`）。

> **⚠️ 工程避坑**：`ip helper-address`默认转发DHCP、TFTP、DNS、NetBIOS等8种UDP广播。其中NetBIOS（UDP 137/138）极易引发跨VLAN广播风暴。生产环境必须用`no ip forward-protocol udp 137`精确控制。

## 四、DORA流程详解（附Option 54关键细节）

DORA是DHCP最重要的概念：Discover（发现）→ Offer（提供）→ Request（请求）→ Acknowledge（确认）。

1. **DHCP Discover（广播）**：客户端广播寻找DHCP服务器。若设置了Broadcast标志位（现代OS默认设置），告知服务器必须以广播回复。
2. **DHCP Offer（广播/单播）**：服务器回复可用配置。通常因Discover携带Broadcast=1，故为广播。
3. **DHCP Request（关键细节——Option 54）**：客户端广播（首次获取）或单播（续租阶段）发出Request。**Option 54（Server Identifier）**明确填写所选服务器的IP地址。未被选中的服务器看到Option 54不是自己，立即撤销预留的IP。
4. **DHCP ACK**：服务器确认配置生效。

## 五、DHCP报文结构（攻防视角）

核心字段包括：
- **`giaddr`（中继代理IP）**：攻击者若伪造此字段，可绕过基于源IP的DHCP Server访问控制。
- **`chaddr`（客户端MAC）**：Starvation攻击的核心——伪造不同MAC填满地址池。
- **Option 54**：Rogue DHCP攻击中，客户端通过此字段声明所选服务器。
- **Option 55/60**：客户端请求的参数列表与厂商标识，可用于**操作系统指纹识别**。

## 六、攻击手法详解（内网渗透入口）

> ⚠️ **风险提示**：以下攻击技术会导致大面积断网或流量劫持，严禁在生产环境或未授权环境模拟。

### 1. DHCP Starvation（饥饿攻击）与 CAM表溢出
- **原理**：伪造海量不同MAC地址的Discover请求，耗尽DHCP Server地址池。
- **副作用**：伪造的海量MAC地址会**迅速填满交换机的CAM表**，导致交换机退化为Hub，未知单播流量泛洪，攻击者可借此被动嗅探同VLAN流量。
- **防御**：Port Security限制单端口MAC数量 + DHCP Snooping限速。

### 2. Starvation + Rogue DHCP Server（红队核心组合攻击）
攻击者先耗尽合法服务器地址池，使新客户端无法获取IP。随后部署Rogue DHCP Server响应请求。因合法服务器无竞争，客户端被迫接受恶意配置（如被分配攻击者IP作为网关/DNS），实现隐蔽MITM。

### 3. DHCP Release伪造攻击（踢人下线）
- **原理**：伪造目标MAC地址发送DHCP Release报文。
- **平台差异**：Windows DHCP Server收到Release后立即回收IP；ISC DHCPd（Linux）默认忽略Release。
- **红队价值**：针对VIP主机精确打击，比全局DoS更隐蔽。

### 4. IPv6盲区——SLAAC/RA伪造攻击（非DHCPv6）
- **原理**：攻击者发送伪造的ICMPv6 RA（Router Advertisement），携带`Default Router Preference = High`，引导客户端将默认网关指向攻击者。
- **协议澄清**：该攻击利用的是IPv6的无状态地址自动配置（SLAAC，RFC 4861）机制，**属于ICMPv6范畴，而非DHCPv6协议**。但因其在IPv6环境中起到网关分配作用，常作为DHCPv4防御的平行盲区被利用。
- **防御**：启用**IPv6 RA Guard**（`ipv6 nd raguard`）。

## 七、DHCP防御纵深

### 1. DHCP Snooping（企业网基石）
交换机监听DHCP流量，建立合法绑定表（`IP | MAC | 端口 | VLAN | 租期`）。
- **信任端口**：连接合法DHCP Server的上联端口。
- **非信任端口**：客户端端口。收到Offer/Acknowledge直接丢弃。

> **⚠️ 避坑指南**：配置Snooping时，交换机互联的Trunk口通常需设为Trust，否则跨交换机的DHCP Offer会被错误丢弃。

### 2. 限速与端口安全
非信任端口配置DHCP报文速率上限（如10 pps）并限制MAC数量，从源头阻止Starvation填满绑定表或CAM表。

### 3. DAI（Dynamic ARP Inspection）
结合DHCP Snooping绑定表，校验ARP报文的IP/MAC合法性，阻止Rogue Server下发的恶意网关ARP解析。

> **⚠️ 绕过DHCP Snooping的对抗**：当绑定表被Starvation填满时，行为因厂商而异。Cisco Catalyst默认fail-close（丢弃新DHCP）；部分中低端国产设备可能fail-open（放行所有DHCP）。因此**限速配置是绝对前提**。

## 八、DHCP协议安全基线检查清单

| 检查项 | 基线标准 | 验证命令（Cisco） |
|:---|:---|:---|
| DHCP Snooping | 全局及VLAN启用 | `show ip dhcp snooping` |
| DHCP Snooping限速 | 非信任端口≤10 pps | `show ip dhcp snooping interface Gi0/1` |
| Port Security | 接入端口MAC≤2 | `show port-security interface Gi0/1` |
| DAI联动 | 绑定表存在且一致 | `show ip dhcp snooping binding` |
| IPv6 RA Guard | 启用（如需IPv6） | `show ipv6 nd raguard` |
| Relay 精确控制 | 移除UDP 137/138转发 | `show run | include forward-protocol` |

## 九、实战抓包分析（Wireshark）

```bash
# 抓取所有DHCP流量
tcpdump -i eth0 -nn 'udp port 67 or udp port 68' -w dhcp.pcap
```

**异常检测指标**：
- 单源MAC发出海量Discover → 疑似Starvation。
- 非授权IP发出Offer/ACK → 疑似Rogue DHCP Server。
- 异常Option 54值 → 疑似欺骗。

## 十、总结

控制DHCP = 控制“身份的源头”。理解DORA流程、Option 54细节、Starvation与Rogue组合攻击、IPv6 SLAAC盲区，是内网渗透入门的第一步。防御方需部署**DHCP Snooping + 限速 + Port Security + DAI**的四层组合，并务必检查IPv6安全策略是否为空白。下一步，建议将DHCP与ARP欺骗、DNS劫持串联，构建完整的网络层与应用层联动防御视角。

## 参考资料
1. **RFC 2131** — *Dynamic Host Configuration Protocol*（DHCPv4标准）
2. **RFC 4861** — *Neighbor Discovery for IPv6*（SLAAC/RA机制）
3. **RFC 3046** — *DHCP Relay Agent Information Option*（Option 82）
4. **Cisco DHCP Snooping Configuration Guide**

---

*本文修订于2026年8月，基于Ubuntu 22.04 LTS / Cisco IOS 15.2环境验证。DHCP行为因操作系统及厂商实现存在差异，生产环境中请以具体设备文档为准。*
