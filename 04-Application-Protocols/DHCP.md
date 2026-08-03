# DHCP 学习笔记

## 一、DHCP 是什么？

**DHCP** 全称：Dynamic Host Configuration Protocol（动态主机配置协议）

**作用**：自动给客户端分配网络配置参数

包括：
- IP 地址
- 子网掩码
- 默认网关
- DNS 服务器
- 租期
- 域名信息

例如：你电脑刚连接公司 WiFi，刚开始 IP、网关、DNS 都是未知。电脑发送 DHCP 请求后，服务器回复：你的IP 192.168.1.100，网关 192.168.1.1，DNS 8.8.8.8，租期 8小时。于是你可以上网。

---

## 二、为什么需要 DHCP？

以前没有 DHCP，管理员需要手动配置每台电脑的 IP、掩码、网关、DNS。1000台电脑怎么办？所以 DHCP 自动化。

---

## 三、DHCP 工作在哪一层？

DHCP 是**应用层协议**，使用 **UDP 67** 端口（服务器）和 **UDP 68** 端口（客户端）。

> 记忆：Server = 67，Client = 68

---

## 四、DHCP 的角色

1. **DHCP Client（客户端）**  
   例如：Windows电脑、手机、Linux机器，负责请求 IP。

2. **DHCP Server（服务器）**  
   负责分配 IP、管理地址池、保存租约。例如路由器通常就是 DHCP Server。

3. **DHCP Relay（中继）**  
   解决 DHCP 服务器不在同一个广播域的问题。因为 DHCP Discover 是广播，广播不能跨路由器，所以使用 DHCP Relay 转发。

   Cisco 配置：
   ```cisco
   interface vlan 10
   ip helper-address DHCP服务器IP
   ```

---

## 五、DHCP 四步流程（DORA）

DORA 是 DHCP 最重要的概念：

- **D** = Discover（发现）
- **O** = Offer（提供）
- **R** = Request（请求）
- **A** = Acknowledge（确认）

### 1. DHCP Discover

客户端第一次上线，不知道 IP 和 DHCP 服务器在哪里，所以广播：

- 目标MAC: `FF:FF:FF:FF:FF:FF`
- 内容：有没有DHCP服务器？我需要IP

> 类似：「谁能给我一个地址？」

### 2. DHCP Offer

DHCP 服务器回复，告诉客户端可以分配的配置：

- IP: 192.168.1.50
- Mask: 255.255.255.0
- Gateway: 192.168.1.1
- DNS: 8.8.8.8

如果有多个 DHCP 服务器，客户端会收到多个 Offer，选择一个。

### 3. DHCP Request

客户端广播：「我要 192.168.1.50」，告诉所有 DHCP 服务器「我选择 A 服务器」。其他服务器撤销 Offer。

### 4. DHCP ACK

服务器确认：「好的，192.168.1.50 给你，有效期 8 小时」。客户端配置完成。

---

## 六、DHCP 数据包内容

一个 DHCP 包包含：
- **Client MAC**：客户端 MAC 地址
- **Your IP Address**：服务器分配的 IP
- **Gateway**：默认网关
- **DNS**：DNS 服务器
- **Lease Time**：租期（例如 86400 秒）

---

## 七、DHCP 租约机制

DHCP 不是永久分配。例如服务器分配 IP 192.168.1.100，租期 24 小时。客户端使用 12 小时后尝试续租：

```text
客户端 → DHCP Request
服务器 → DHCP ACK
```

继续使用。

---

## 八、DHCP 和 ARP 的关系

这两个协议经常一起出现：

| 协议 | 解决的问题 |
|------|-----------|
| DHCP | 解决「我是谁？我的IP是多少？」 |
| ARP  | 解决「这个IP对应哪个MAC？」 |

**流程**：  
电脑启动 → DHCP 获得 IP → ARP 查询网关 MAC → 通信

---

## 九、DHCP 饥饿攻击（DHCP Starvation）

### 原理

DHCP 服务器地址池有限（例如 192.168.1.100-200，只有 100 个 IP）。  
攻击者疯狂发送伪造不同 MAC 的 DHCP 请求，服务器不断分配 IP，最后地址池耗尽，正常用户无法获取 IP。

### 攻击工具

- **yersinia**：支持多种二层攻击
- **dhcpstarv**：专用 DHCP 饥饿工具
- **Metasploit**：`auxiliary/dos/dhcp/dhcp_dos`

### 攻击效果

- 地址池耗尽
- 正常用户无法获取 IP
- 网络中断（DoS 攻击）

---

## 十、DHCP 欺骗攻击（Rogue DHCP）

### 原理

攻击者插入一个"恶意 DHCP Server"，用户广播 Discover 时，两个服务器都回应 Offer：

| 服务器 | 提供的配置 |
|--------|-----------|
| 合法服务器 | IP 192.168.1.20，Gateway 192.168.1.1 |
| 攻击者 | IP 192.168.1.30，Gateway 攻击者IP |

客户端可能选择攻击者。

### 攻击效果

1. **控制默认网关**  
   设置 Gateway = 攻击者IP，流量路径：用户 → 攻击者 → 真实网关，形成 MITM。

2. **控制 DNS 服务器**  
   设置 DNS = 攻击者，用户访问 bank.com 时解析到攻击者服务器，形成 DNS 劫持。

---

## 十一、DHCP 和 ARP 欺骗区别

| 攻击 | 控制什么 | 发生时机 |
|------|---------|---------|
| ARP 欺骗 | IP → MAC 映射 | 已经联网以后 |
| DHCP 欺骗 | 网络配置分配过程 | 客户端获取配置时 |
| DNS 劫持 | 域名解析 | DNS 查询时 |
| LLMNR 投毒 | 名字解析 | 名称解析时 |

---

## 十二、DHCP 防御

### 1. DHCP Snooping（重点）

交换机监听 DHCP 流量，建立合法绑定表：

```text
IP | MAC | 端口 | VLAN | 租期
```

设置**信任端口**（连接合法 DHCP Server）和**非信任端口**（普通客户端）。  
如果非信任端口发送 DHCP Offer/Acknowledge，交换机直接丢弃。

### 2. Port Security

限制一个端口只能绑定几个 MAC，防止 DHCP Starvation 攻击。

### 3. DAI（Dynamic ARP Inspection）

结合 DHCP Snooping，检查 ARP 是否合法。

---

## 十三、Wireshark 如何分析 DHCP？

过滤器：`dhcp` 或 `bootp`

可以看到：
- **Discover**：`0.0.0.0 → 255.255.255.255`
- **Offer**：服务器 → 客户端
- **Request**：客户端广播
- **ACK**：服务器确认

---

## 十四、内网安全视角总结

你需要形成这个思维链：

```text
客户端上线
    ↓
DHCP（我要网络身份）
    ↓
ARP（IP找MAC）
    ↓
DNS（域名找IP）
    ↓
LLMNR/NBT-NS（局域网名字解析）
    ↓
认证协议（NTLM/Kerberos）
    ↓
横向移动
```

这就是企业内网攻击链。

---

## 十五、学习 DHCP 应该重点掌握

- ✅ DHCP DORA 流程
- ✅ UDP 67/68
- ✅ DHCP 广播机制
- ✅ DHCP Relay
- ✅ DHCP Snooping
- ✅ DHCP Starvation 攻击原理
- ✅ Rogue DHCP Server
- ✅ DHCP 与 ARP 关系
- ✅ Wireshark 分析 DHCP 包
