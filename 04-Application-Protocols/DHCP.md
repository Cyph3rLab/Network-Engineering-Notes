# DHCP协议深度解析：从DORA流程到内网渗透入口攻击实战

> **文档定位**：本文档面向内网安全与红蓝对抗方向，从DHCP协议的核心功能出发，逐层深入到DORA流程、攻击手法、防御机制及IPv6盲区，旨在构建完整的“内网协议攻防入口链路”知识闭环。


## 一、DHCP是什么？

**DHCP** 全称：Dynamic Host Configuration Protocol（动态主机配置协议）

**作用**：自动给客户端分配网络配置参数

包括：
- IP地址
- 子网掩码
- 默认网关
- DNS服务器
- 租期（Lease Time）
- 域名信息

**场景示例**：你电脑刚连接公司WiFi，刚开始IP、网关、DNS都是未知。电脑发送DHCP请求后，服务器回复：你的IP是192.168.1.100，网关192.168.1.1，DNS是8.8.8.8，租期8小时。于是你可以上网。


## 二、为什么需要DHCP？

以前没有DHCP，管理员需要手动配置每台电脑的IP、掩码、网关、DNS。1000台电脑需要手动配置1000次，且IP冲突、配置错误频发。DHCP实现了网络配置的**自动化与集中管理**。


## 三、DHCP工作在哪一层？

DHCP工作在**应用层**（使用UDP传输），功能上是网络配置协议。使用 **UDP 67** 端口（服务器）和 **UDP 68** 端口（客户端）。

> 记忆口诀：**Server = 67，Client = 68**


## 四、DHCP的角色

| 角色 | 说明 | 典型设备 |
| :--- | :--- | :--- |
| **DHCP Client（客户端）** | 负责请求IP配置 | Windows电脑、手机、Linux主机 |
| **DHCP Server（服务器）** | 负责分配IP、管理地址池、保存租约 | 路由器、Windows DHCP Server、Linux dhcpd |
| **DHCP Relay（中继）** | 解决DHCP服务器不在同一广播域的问题。DHCP Discover是广播，广播不能跨路由器/VLAN，需中继转发 | 三层交换机、路由器 |


## 五、VLAN环境下的DHCH行为（联动知识）

VLAN划分了广播域，DHCP Discover是广播帧，**无法跨越VLAN边界**。因此：

- **方案一**：每个VLAN部署独立的DHCP Server。
- **方案二**：在VLAN的三层接口上配置**DHCP Relay**，将广播转换为单播转发给中央DHCP Server。

**Cisco配置示例**：
```cisco
interface vlan 10
  ip helper-address 192.168.100.10   ! 指向中央DHCP服务器
```

> **⚠️ 踩坑警告**：`ip helper-address`不仅转发DHCP，还会转发**TFTP、DNS、NetBIOS等7种UDP广播**。若企业网络中有不必要的UDP广播流量，可能意外放大广播域。可使用`ip forward-protocol udp`精确控制转发的UDP协议类型。

**攻击视角**：若攻击者所在VLAN未配置Relay且无合法DHCP Server，可轻松部署Rogue DHCP Server，因无任何竞争。


## 六、DHCP四步流程（DORA）

DORA是DHCP最重要的概念：

- **D** = Discover（发现）
- **O** = Offer（提供）
- **R** = Request（请求）
- **A** = Acknowledge（确认）

### 1. DHCP Discover

客户端第一次上线，不知道IP和DHCP服务器在哪里，所以广播：

- 目标MAC：`FF:FF:FF:FF:FF:FF`
- 目标IP：`255.255.255.255`
- 内容：有没有DHCP服务器？我需要IP

> 类比：「谁能给我一个地址？」

### 2. DHCP Offer

DHCP服务器回复，告诉客户端可以分配的配置：

- IP: 192.168.1.50
- Mask: 255.255.255.0
- Gateway: 192.168.1.1
- DNS: 8.8.8.8
- Lease Time: 86400秒

如果有多个DHCP服务器，客户端会收到多个Offer，选择其中一个。

### 3. DHCP Request（关键字段补充）

客户端广播：「我要192.168.1.50」，告诉所有DHCP服务器「我选择A服务器」。

> **⚠️ 关键细节（Option 54 - Server Identifier）**：
> 客户端在Request报文中通过 **Option 54（Server Identifier）** 字段，**明确填写所选服务器的IP地址**。
> - 被选中的服务器（Option 54指向的那台）→ 准备发送ACK。
> - 未被选中的服务器 → 看到Option 54不是自己，**撤销之前预留的IP**（释放资源）。

### 4. DHCP ACK

服务器确认：「好的，192.168.1.50给你，有效期8小时」。客户端配置完成。


## 七、DHCP数据包内容

一个DHCP包包含的核心字段：

| 字段 | 说明 |
| :--- | :--- |
| **Client MAC** | 客户端MAC地址（唯一标识） |
| **Your IP Address** | 服务器分配的IP |
| **Gateway** | 默认网关（Option 3） |
| **DNS** | DNS服务器（Option 6） |
| **Lease Time** | 租期（Option 51） |
| **Server Identifier** | 所选服务器IP（Option 54，Request阶段关键字段） |


## 八、DHCP租约机制

DHCP不是永久分配。例如服务器分配IP 192.168.1.100，租期24小时。

- **T1（50%租期）**：客户端尝试续租，发送DHCP Request → 若收到ACK，续租成功。
- **T2（87.5%租期）**：若T1未成功，再次尝试续租。
- **租期到期**：若均未成功，IP被收回，客户端需重新Discover。

**续租过程**：
```text
客户端 → DHCP Request（单播，直接发给原服务器）
服务器 → DHCP ACK（续租成功）
```


## 九、DHCP和ARP的关系

这两个协议经常一起出现，是内网通信的“第一关”和“第二关”：

| 协议 | 解决的问题 | 时机 |
| :--- | :--- | :--- |
| **DHCP** | 解决「我是谁？我的IP是多少？」 | 设备上线时 |
| **ARP** | 解决「这个IP对应哪个MAC？」 | 需要通信时 |

**完整流程**：
```text
电脑启动 → DHCP获得IP → ARP查询网关MAC → 开始通信
```


## 十、DHCP饥饿攻击（DHCP Starvation）

### 原理

DHCP服务器地址池有限（例如192.168.1.100-200，只有100个IP）。攻击者使用工具伪造海量不同MAC地址的DHCP Discover请求，服务器不断分配IP，最后地址池耗尽，正常用户无法获取IP。

### 攻击工具

- **yersinia**：支持多种二层攻击
- **dhcpstarv**：专用DHCP饥饿工具
- **Metasploit**：`auxiliary/dos/dhcp/dhcp_dos`

### 攻击效果

- 地址池耗尽
- 正常用户无法获取IP
- 网络中断（DoS攻击）

### 组合攻击：Starvation + Rogue DHCP Server（红队核心手法）

1. 攻击者先发起**DHCP Starvation攻击**，耗尽合法DHCP服务器的地址池。
2. 合法服务器无IP可分配后，新上线的客户端**无法获取IP**。
3. 攻击者此时部署**Rogue DHCP Server**，响应客户端的Discover请求。
4. 因为没有合法服务器的竞争（地址池已空），客户端**被迫接受恶意配置**。

> **效果**：这种组合攻击比单纯的Rogue DHCP更隐蔽——用户会抱怨“网络慢”，但不会怀疑“IP被抢了”，因为看起来是“拿到了IP但网络不通”。


## 十一、DHCP Release伪造攻击（踢人下线）

### 原理

DHCP协议允许客户端发送**DHCP Release**报文主动释放IP（告诉服务器“我不用了”）。

### 攻击利用

攻击者伪造目标主机的MAC地址，发送DHCP Release报文给服务器。服务器收到后，**立即将目标IP标记为可用**，并在租约表中删除对应条目。

### 后果

- 目标主机瞬间断网（IP被收回）
- 攻击者可配合ARP欺骗或Rogue DHCP进行精确劫持

### 红队价值

针对VIP主机（如域控、核心数据库服务器）进行精确打击，比全局DoS更隐蔽。


## 十二、DHCP欺骗攻击（Rogue DHCP）

### 原理

攻击者部署一个“恶意DHCP Server”，用户广播Discover时，两个服务器都回应Offer：

| 服务器 | 提供的配置 |
| :--- | :--- |
| 合法服务器 | IP 192.168.1.20，Gateway 192.168.1.1 |
| 攻击者 | IP 192.168.1.30，Gateway 攻击者IP |

客户端可能选择攻击者（取决于谁先响应、Offer中的参数）。

### 攻击效果

1. **控制默认网关**：设置Gateway = 攻击者IP，流量路径：用户 → 攻击者 → 真实网关，形成MITM。
2. **控制DNS服务器**：设置DNS = 攻击者，用户访问bank.com时解析到攻击者钓鱼服务器，形成DNS劫持。


## 十三、DHCP与ARP/LLMNR欺骗的区别

| 攻击 | 控制什么 | 发生时机 |
| :--- | :--- | :--- |
| **ARP欺骗** | IP → MAC映射 | 已经联网以后 |
| **DHCP欺骗** | 网络配置分配过程 | 客户端获取配置时 |
| **DNS劫持** | 域名解析 | DNS查询时 |
| **LLMNR投毒** | 名字解析 | 名称解析时 |


## 十四、DHCP防御

### 1. DHCP Snooping（重点——企业网基石）

交换机监听DHCP流量，建立合法绑定表：

```text
IP | MAC | 端口 | VLAN | 租期
```

**配置逻辑**：
- 设置**信任端口（Trusted）**：连接合法DHCP Server的端口。
- 设置**非信任端口（Untrusted）**：普通客户端端口。
- 若非信任端口发送DHCP Offer/Acknowledge，交换机**直接丢弃**。

> **⚠️ DHCP Snooping是DAI（动态ARP检测）的数据来源基石**：没有DHCP Snooping绑定表，DAI无法校验ARP的真实性。

### 2. Port Security

限制一个端口只允许学习指定数量的MAC（如1-2个），防止DHCP Starvation攻击伪造大量MAC。

### 3. DHCP Snooping限速（防绕过）

配置每个端口每秒的DHCP报文数量上限（如10 pps），防止攻击者通过海量请求填满绑定表。

### 4. DAI（Dynamic ARP Inspection）

结合DHCP Snooping绑定表，校验ARP报文中的IP/MAC是否合法，不一致则丢弃。

### ⚠️ 攻击者如何绕过DHCP Snooping？（蓝队必知）

1. 攻击者发起**DHCP Starvation攻击**，用海量伪造MAC快速耗尽地址池。
2. **同时**，交换机DHCP Snooping的绑定表也被海量伪MAC请求填满（绑定表有容量上限）。
3. 绑定表满后，某些交换机进入**降级模式（Fallback）**：不再校验非信任端口的DHCP报文，直接放行。
4. 此时攻击者部署的**Rogue DHCP Server**成功分配恶意配置，绕过DHCP Snooping。

**防御**：配置DHCP Snooping限速（限制每个端口每秒的DHCP报文数）+ Port Security。


## 十五、IPv6环境下的DHCP盲区（红队必看）

你的安全策略可能只覆盖了IPv4！

### IPv6下的变化

- **DHCPv6**：UDP 546（客户端）/ 547（服务器），与DHCPv4差异较大。
- **SLAAC（无状态地址自动配置）**：IPv6主机可以**不依赖DHCPv6**，仅通过**RA（Router Advertisement，路由器通告）**获取网络前缀，自动生成IPv6地址。

### 攻击视角

如果企业只审计了IPv4的DHCP流量：
1. 攻击者在内网发送伪造的**ICMPv6 RA（路由器通告）**。
2. 内网主机（默认启用IPv6）收到RA后，自动配置IPv6地址，并将默认网关指向攻击者。
3. 所有IPv6流量被劫持，**完全绕过基于IPv4的DHCP Snooping、DAI、防火墙策略**。

### 防御

- 在主机/交换机上禁用不必要的IPv6。
- 配置**IPv6 RA Guard**，阻止非法RA通告。
- 在NDR（网络检测响应）设备上监控异常的ICMPv6流量。


## 十六、内网安全视角总结（攻击链思维）

```text
客户端上线
    ↓
DHCP（我要网络身份）          ← 本篇
    ↓
ARP（IP找MAC）               ← 已学
    ↓
DNS（域名找IP）              ← 待学
    ↓
LLMNR/NBT-NS（局域网名字解析） ← 已学（UDP 137/5353）
    ↓
认证协议（NTLM/Kerberos）     ← 待学
    ↓
横向移动                     ← 终极目标
```

这就是企业内网攻击链。DHCP是这条链的**第一环**——控制DHCP，就控制了“身份的源头”。


## 十七、学习DHCP应该重点掌握

- ✅ DHCP DORA流程（含Option 54 Server Identifier细节）
- ✅ UDP 67/68端口
- ✅ DHCP广播机制与广播域限制
- ✅ VLAN环境下DHCP Relay的必要性
- ✅ DHCP租约机制（T1/T2）
- ✅ DHCP Snooping原理与配置
- ✅ DHCP Starvation攻击原理
- ✅ **Starvation + Rogue DHCP Server组合攻击**
- ✅ **DHCP Release伪造攻击**
- ✅ DHCP Snooping的绕过手法（绑定表满降级）
- ✅ DHCP与ARP/DAI的联动关系
- ✅ **IPv6环境下SLAAC/RA攻击盲区**
- ✅ Wireshark分析DHCP包


## 参考资料

- RFC 2131 - Dynamic Host Configuration Protocol
- RFC 3315 - DHCPv6
- RFC 4861 - Neighbor Discovery for IPv6（SLAAC/RA）
- Cisco DHCP Snooping Configuration Guide
- MITRE ATT&CK - T1046 Network Service Scanning


**总结**：DHCP是企业内网“第一个被调用的协议”，也是内网渗透的“入口级攻击面”。掌握DORA流程、Option 54字段、Starvation + Rogue组合攻击、Release伪造以及IPv6盲区渗透，是理解内网攻击链的起点。修复本文提到的所有硬伤并补充组合攻击与IPv6盲区后，它将与你之前学习的ARP、VLAN、IPv6文章形成完整的“内网协议攻防入口链路”，为后续学习DNS劫持、NTLM中继和横向移动打下坚实基础。继续向前！
