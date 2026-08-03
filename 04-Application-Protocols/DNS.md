# DNS 学习笔记

## 一、DNS 是什么？

**DNS**：Domain Name System（域名系统）

**作用**：将域名解析成 IP 地址

例如你访问 www.baidu.com，计算机不知道这个名字，需要 DNS 将其转换为 180.xxx.xxx.xxx。

---

## 二、为什么需要 DNS？

早期互联网使用 IP 地址（如 192.168.1.10），但人类难以记忆。所以出现 DNS，类似手机通讯录：张三 → 138xxxxxxxx。

---

## 三、DNS 工作在哪一层？

DNS 是**应用层协议**。

- **UDP 53** 端口：普通查询
- **TCP 53** 端口：区域传送、大响应、DNSSEC

---

## 四、DNS 的基本结构

DNS 是一个树形结构：

```text
.
├── com
├── cn
└── org
    └── example.com
        └── www.example.com
```

**完整域名分解**：
- `www`：主机名
- `example`：域名
- `com`：顶级域

---

## 五、DNS 查询角色

1. **DNS Client（客户端）**  
   你的电脑、手机，负责发送查询。

2. **Local DNS Resolver（本地DNS解析器）**  
   运营商 DNS（114.114.114.114、8.8.8.8）或路由器（192.168.1.1），帮你递归查询。

3. **Root DNS（根服务器）**  
   负责告诉你 `.com`、`.cn` 在哪里。

4. **TLD DNS（顶级域服务器）**  
   例如 `.com` DNS、`.cn` DNS。

5. **Authoritative DNS（权威DNS）**  
   真正保存域名对应 IP 的服务器。

---

## 六、DNS 查询流程

假设访问 `www.example.com`：

### 第一步：查询本地缓存

检查 `hosts` 文件和 DNS 缓存。
- Linux: `/etc/hosts`
- Windows: `C:\Windows\System32\drivers\etc\hosts`

### 第二步：请求本地DNS服务器

发送 DNS Query。

### 第三步：递归查询根服务器

根服务器不知道具体 IP，但告诉你 `.com` DNS 在哪里。

### 第四步：查询顶级域

问 `.com` DNS，返回 `example.com` 的权威 DNS。

### 第五步：查询权威DNS

问 `example.com` DNS，返回 `www.example.com` 的 IP。

### 第六步：返回客户端

最终 `www.example.com` → `93.xxx.xxx.xxx`

---

## 七、DNS 记录类型（重点）

| 记录类型 | 说明 | 示例 |
|---------|------|------|
| **A** | IPv4 地址 | `www.example.com → 192.168.1.10` |
| **AAAA** | IPv6 地址 | `www.example.com → 2001:db8::1` |
| **CNAME** | 别名 | `www.baidu.com → www.a.shifen.com` |
| **MX** | 邮件服务器 | `example.com → mail.example.com` |
| **NS** | 指定 DNS 服务器 | `example.com → ns1.example.com` |
| **TXT** | 文本信息，用于 SPF、DKIM、域验证 | `v=spf1 include:_spf.google.com ~all` |
| **PTR** | 反向解析（IP → 域名） | 与 A 记录相反 |

---

## 八、DNS 缓存

DNS 为了速度会缓存。第一次查询后保存，TTL 有效期内直接使用。

---

## 九、TTL 是什么？

**TTL（Time To Live）** 表示缓存多久。  
例如 A 记录 TTL=3600，表示缓存 1 小时。

---

## 十、DNS 与 DHCP 的关系

DHCP 负责告诉你 DNS 服务器是谁。  
例如 DHCP ACK 中包含 `DNS: 8.8.8.8`。  
然后 DNS 负责域名 → IP 的转换。

---

## 十一、DNS 攻击

### 1. DNS 缓存投毒（DNS Cache Poisoning）

- 正常：DNS 将 `bank.com` 解析为真实 IP。
- 攻击者伪造 `bank.com → 攻击者IP`，DNS 缓存被污染。  
  用户访问 `bank.com` 实际访问攻击者服务器。

### 2. DNS 欺骗（DNS Spoofing）

攻击者伪造 DNS 响应，抢先回复客户端，让域名解析到攻击者 IP。

### 3. DNS 劫持

常见于 DHCP 攻击，攻击者分配恶意 DNS 服务器，所有 DNS 请求都经过攻击者。

### 4. DNS 隧道（DNS Tunnel）

利用 DNS 传输数据，把数据藏在子域名中（如 `a8sd78as.attacker.com`），用于 C2 通信和数据外传。

### 5. DNS 区域传送泄露

DNS 服务器同步（Zone Transfer）配置错误，攻击者可获取所有域名、服务器 IP、内部主机信息。

---

## 十二、内网中的 DNS

企业环境通常：`客户端 → 内部 DNS 服务器 → Active Directory DNS`

域环境大量依赖 DNS，例如加入域时通过查询 `_ldap._tcp.dc._msdcs.corp.local` 找到域控。

---

## 十三、DNS 与 LLMNR/NBT-NS 的关系

Windows 名字解析顺序：`DNS → LLMNR → NBT-NS`

如果 DNS 失败，Windows 会广播 LLMNR 请求，攻击者可以响应，这就是 **LLMNR 投毒**。

---

## 十四、DNS 和内网攻击链

```text
进入内网 → DHCP攻击 → 修改DNS → DNS劫持 → 获取账号 → NTLM Relay → 域横向移动
```

---

## 十五、防御 DNS 攻击

1. **使用安全 DNS 服务器**  
   BIND 安全配置、Windows DNS 安全配置。

2. **DNSSEC（DNS 签名）**  
   防止 DNS 响应被篡改。

3. **禁止递归查询暴露**  
   公网 DNS 不要允许任何人递归查询。

4. **DNS 日志审计**  
   监控异常域名（如 `aaaa123.attacker.com`）。

5. **DHCP Snooping**  
   防止攻击者修改 DNS 服务器。

6. **禁止内部主机直接访问外部 DNS**  
   企业客户端只能使用内部 DNS。

---

## 十六、DNS 实验分析

**Wireshark 过滤器**：`dns`

- 查看请求：`Standard query A www.baidu.com`
- 查看响应：`Standard query response A 180.xxx.xxx.xxx`

---

## 十七、内网安全学习重点

- [ ] ✅ DNS 查询流程
- [ ] ✅ UDP/TCP 53
- [ ] ✅ A/CNAME/MX/NS/TXT/PTR
- [ ] ✅ TTL
- [ ] ✅ DNS 缓存
- [ ] ✅ DNS 欺骗
- [ ] ✅ DNS 缓存投毒
- [ ] ✅ DNS 劫持
- [ ] ✅ DNS 隧道
- [ ] ✅ AD 环境 DNS 作用
- [ ] ✅ DNS 与 LLMNR 关系
