# IP协议深度解析：从协议解剖到分片攻击与内网防御实战

> **实验环境**：Ubuntu 22.04.3 LTS / Kali Linux 2025.1 / Windows 11 22H2 / Wireshark 4.2.6 / Cisco IOS 15.9(3)M（模拟器）
>
> **合规声明**：本文所有攻击技术描述**仅限用于网络安全防护研究与获得书面授权的隔离环境安全测试**。未经授权的IP欺骗、分片攻击、网络嗅探等行为，违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条，切勿用于非法目的。


## 一、核心概念与类比（IP的本质是什么？）

整个网络世界可类比为**邮政系统**：
- **MAC地址（二层）** ：相当于**身份证号**，出厂即定，用于在同一栋楼（广播域）内精准识别住户。
- **IP地址（三层）** ：相当于**邮寄地址**。这个地址是逻辑的、可变的，但它能跨城市（跨网络）将包裹送到你手上。

**IP协议的核心任务只有两个：**
1. **寻址**：给每一台接入网络的设备分配一个逻辑上的“门牌号”。
2. **分片与重组**：当数据包太大，超过出口链路的MTU时，IP负责将其切成小块发送，到达目的地后再拼装还原。

IP协议是**无连接**和**尽力而为**的——只管发，不保证不丢包、不保证按顺序到达。可靠性保障由上层协议（TCP）负责。


## 二、技术细节解剖：IPv4数据包的“基因序列”

IPv4头部长度通常为**20字节**（不含选项字段）。以Wireshark抓取的一个IPv4包为例（十六进制字节流）：
`45 00 00 3C 1A 2B 40 00 40 06 7C D1 C0 A8 01 0A C0 A8 01 14`

| 字段 | 长度 | 取值示例 | 工程师灵魂解析（攻防视角） |
|:---|:---:|:---|:---|
| **Version** | 4 bit | `4` | IPv4。防火墙可基于此直接丢弃非预期版本包。 |
| **IHL** | 4 bit | `5` | 5 × 4字节 = 20字节（无选项）。带选项（如源路由）的包可能触发安全告警或直接丢弃。 |
| **ToS** | 8 bit | `00` | 现为DSCP和ECN。攻击者可能伪造高优先级DSCP绕过限速，或设置ECN=3（CE）诱导TCP降速（DoS变种）——**但该攻击仅在目标主机启用了ECN（`tcp_ecn=1`）且双方成功协商ECN时才生效**。防御可禁用ECN（`net.ipv4.tcp_ecn=0`）。 |
| **Total Length** | 16 bit | `0x003C`=60 | IP包总长度。若超过MTU且DF=0则触发分片。 |
| **Identification** | 16 bit | `0x1A2B` | 同一数据包的所有分片共享此ID。现代OS采用随机化ID防Idle扫描。 |
| **Flags** | 3 bit | `010` | DF=1, MF=0。DF=1且超MTU时触发ICMP Type 3 Code 4（PMTUD核心）。 |
| **Fragment Offset** | 13 bit | `0` | 以8字节为单位。Teardrop攻击利用重叠偏移导致重组崩溃（CVE-1999-0015）。 |
| **TTL** | 8 bit | `40`=64 | 每跳减1防环。TTL初始值在不同OS中确有默认差异，但**单一TTL不可作为可靠OS指纹**（参见第5.1节）。 |
| **Protocol** | 8 bit | `0x06`=TCP | 标识载荷类型。防火墙ACL基于此匹配。 |
| **Header Checksum** | 16 bit | `0x7CD1` | 仅校验头部。因TTL每跳变化，需逐跳重算。 |
| **Source IP** | 32 bit | `192.168.1.10` | IP欺骗核心目标。防御依赖uRPF。 |
| **Destination IP** | 32 bit | `192.168.1.20` | 路由器查表转发唯一依据。 |


## 三、IP转发与路由决策

三层设备收到IP包后执行以下流程：
1. 检查TTL，若≤0丢弃并返回ICMP Type 11（Time Exceeded）。
2. 校验和检查（IPv4头部）。
3. **最长前缀匹配（LPM）** ：在路由表中查找匹配长度最长的条目（RIB→FIB）。
4. TTL减1，重算校验和，转发至下一跳。

> **安全关联**：攻击者可利用TTL为0或伪造TTL跳跃值绕过某些基于TTL的安全检测。


## 四、分片与重组机制：IP最精妙也最危险的地方

### 4.1 为什么要分片？

以太网能传输的最大数据帧为**1500字节（MTU）** 。若IP包总长度超过MTU且DF=0，IP层必须分片。若DF=1，路由器丢弃该包并返回ICMP Type 3 Code 4（Fragmentation Needed）。

### 4.2 切分与重组逻辑（精确计算）

假设IP包总长度=3000字节，IP头20字节，则载荷为2980字节。以太网MTU=1500，单分片最大载荷为1480字节。需切成**三个分片**：

| 分片 | 总长度 | MF标志 | 偏移量(×8字节) | 8字节对齐校验 | 载荷起始位置 |
|:---|:---:|:---:|:---:|:---:|:---|
| 分片1 | 1500字节 | 1 | 0 | ✅ (0/8=0) | 0 |
| 分片2 | 1500字节 | 1 | 185 | ✅ (1480/8=185) | 1480字节处 |
| 分片3 | 40字节 | 0 | 370 | ✅ (2960/8=370) | 2960字节处 |

接收端根据四元组（源IP，目的IP，协议号，ID）唯一确定原始包，按偏移量排序拼装后交付上层。

### 4.3 攻防演进

| 攻击手法 | 原理 | 现代防御状态 |
|:---|:---|:---|
| **重叠分片攻击（Teardrop）** | 第二分片偏移量小于前一分片尾部，导致重组时整数溢出 | **主流现代OS（Windows 10+、Linux 5.x+）已修复**，但工控/老旧嵌入式设备仍有风险。建议在IDS层面保留重叠分片检测作为深度防御 |
| **极小分片攻击（Tiny Fragment）** | 首分片仅含IP头不含四层端口，无状态防火墙无法判断端口 | **仅对无状态ACL有效**——现代状态防火墙（含Linux conntrack）执行虚拟重组，**但若防火墙因性能压力关闭虚拟重组，则仍可被绕过** |
| **分片耗尽攻击** | 发送大量不完整分片，耗尽防火墙重组缓存 | 配置重组超时（`ipfrag_time`）和内存上限（`ipfrag_high_thresh`）防耗尽 |

**虚拟重组防御配置（Linux）** ：
```bash
# 设置分片重组超时（默认30秒）
sysctl -w net.ipv4.ipfrag_time=30
# 设置分片重组缓存上限（默认4194304字节≈4MB）
sysctl -w net.ipv4.ipfrag_high_thresh=2097152  # 降至2MB防耗尽
```

### 4.4 IP分片攻击检测规则

> **⚠️ 适用场景提示**：该规则在IDC等大流量环境中可能产生大量告警（分片属正常现象），建议结合`threshold`参数或`suppression`白名单进行调优。IPv6环境中需根据扩展头长度调整`dsize`阈值。

以下为Snort/Suricata兼容的异常首分片检测规则：

```yaml
# 检测极小首分片攻击（载荷过小，无法包含完整TCP/UDP端口）
alert ip any any -> any any (
  msg:"SUSPICIOUS TINY FIRST FRAGMENT - Potential evasion attempt";
  fragbits:M;              # 匹配More Fragments标志位为1（有后续分片）
  frag_offset:0;           # 确保是首分片（偏移为0）
  dsize:<20;               # IP载荷小于20字节（不足TCP 20字节头或UDP 8字节头）
  sid:2100001; rev:1;
)
```

*注：主流现代操作系统的Teardrop重叠分片防护已由内核接管，**但在工控或混合OS环境中，建议在IDS层面保留重叠分片检测规则作为深度防御**，防范利用“主机与IDS重组策略差异”的逃逸攻击。*


## 五、内网攻防视角下的IP（红蓝对抗）

### 5.1 攻击者视角（红队）

| 技术 | 描述 | 现代有效性评估 |
|:---|:---|:---|
| **IP欺骗** | 伪造源IP发起DDoS反射攻击或绕过基于IP的信任ACL | 仍然有效，但防御（uRPF）在运营商网络中普及率提升 |
| **TTL辅助指纹** | 通过初始TTL值推断OS（Linux 64，Windows 128） | **仅限辅助线索**——管理员可自定义（Linux: `net.ipv4.ip_default_ttl`，Windows注册表`DefaultTTL`），路径跳数不可预知，**单一TTL不可靠**。Nmap OS检测依赖13+项TCP/IP堆栈组合特征（窗口大小、选项顺序、MSS等），TTL仅是其中之一 |
| **TTL操纵绕过IDS** | 构造TTL=1的包使IDS与接收端对包生命周期的判定不一致 | 针对某些老旧IDS有效，现代NDR已考虑此问题 |

### 5.2 防守者视角（蓝队）

1. **防IP欺骗——uRPF（需根据路由模式选择模式）** ：

| uRPF模式 | 检查逻辑 | 适用场景 | Linux配置 | Cisco配置 |
|:---|:---|:---|:---|:---|
| **严格模式（Strict）** | 源IP路由出接口必须**等于**接收接口 | 对称路由网络 | `rp_filter=1` | `rx` |
| **松散模式（Loose）** | 源IP在路由表中**存在**即可 | 非对称路由/多出口 | `rp_filter=2` | `any` |
| **禁用** | 不检查 | 默认（Linux） | `rp_filter=0` | — |

> **⚠️ 部署警告**：在启用`rp_filter=1`之前，**必须确认网络路由为对称模式**，否则将阻断合法流量，导致大面积通信中断。
>
> **如何验证网络路由是否对称**：
> - 从被保护的子网发起流量，`traceroute -n <目标>` 记录去程路径的下一跳；
> - 从目标端反向执行`traceroute -n <源>` 记录回程路径的下一跳；
> - 若去程和回程经过的**下一跳IP或出接口不同**，则为**非对称路由**，此时不得使用严格模式。
> - 在生产环境中，建议先在**测试子网**上启用`rp_filter=1`并观察1-2天，确认无异常后再推广至全网。

2. **分片重组检查**：防火墙配置强制重组（见4.3节），设置重组超时和内存上限防耗尽。
3. **IP选项丢弃**：边界路由器直接丢弃带Source Route等选项的包（Cisco：`ip options drop`；Linux：`net.ipv4.conf.all.accept_source_route=0`）。


## 六、避坑指南与进阶延伸

### 坑1：认为“Ping不通”就是“IP不通”

服务器可能禁Ping（丢弃ICMP），但TCP 80/443开放。可靠测法：
```bash
# 方式1：仅TCP SYN Ping探测（不进行端口扫描）
nmap -sn -PS80,443 192.168.1.1
# -sn 表示“跳过端口扫描”，-PS80,443 表示“使用TCP SYN探测80和443端口”

# 方式2：直接TCP连接测试（更直接）
nc -zv 192.168.1.1 80
```

### 坑2：认为NAT会导致所有IPsec流量无法穿越（❌ 常见误区）

| IPsec模式 | NAT穿越能力 | 说明 |
|:---|:---:|:---|
| **AH模式** | ❌ 无法穿越 | AH对整个IP头+载荷做校验，NAT修改IP头后校验失败 |
| **ESP模式（无NAT-T）** | ❌ 无法穿越 | 端口号冲突（ESP协议号50 vs NAT端口映射） |
| **ESP模式 + NAT-T（RFC 3948）** | ✅ **可以穿越** | 将ESP封装在UDP 4500中，**现代IPsec VPN默认启用** |

**正确认知**：IPsec的**ESP模式通过NAT-T（UDP 4500封装）可以正常穿越NAT**。若在NAT环境中部署IPsec，检查两端是否启用NAT-T（StrongSwan: `nat-traversal=yes`）以及UDP 4500是否被防火墙阻断。同时注意NAT设备需正确映射UDP 4500端口（非标准端口时需额外配置）。

### 坑3：PMTUD黑洞

若DF=1且包超MTU，路由器返回ICMP Type 3 Code 4。若该ICMP被防火墙拦截，则TCP连接卡死。现代TCP协议栈通过**PLPMTUD（RFC 8899）** 主动探测包大小来缓解：
```bash
# 启用TCP MTU探测（值说明：0=禁用，1=仅在PMTUD失败时探测，2=始终积极探测）
sysctl -w net.ipv4.tcp_mtu_probing=1
# 注意：该机制依赖ICMP可达性；若路径ICMP被完全阻断，建议同时启用tcp_mtu_probing=2并配合MSS钳制
```


## 七、IPv6头部简要对比

| 特性 | IPv4 | IPv6（RFC 8200） |
|:---|:---|:---|
| 头部长度 | 20–60字节（可变） | 40字节（固定） |
| 分片机制 | 内置在基础头部中 | 移至**分片扩展头**（需单独处理） |
| 校验和 | 有（仅头部） | **无**（依赖链路层和传输层） |
| IPsec支持 | 可选（AH/ESP作为独立协议） | 可选（AH/ESP作为扩展头实现）——**早期RFC 1883曾将IPsec列为IPv6强制组件，但RFC 8200已将其降级为可选**。IPv6的扩展头架构为IPsec提供了更统一的封装位置，但这**不意味着部署更简便**——实际部署瓶颈仍是密钥管理和IKE协商 |

> **IPv6分片安全提醒**：IPv6分片扩展头同样存在重叠分片等攻击风险（CVE-2020-16898），且重组内存消耗更大（扩展头处理复杂），需在防火墙中配置相应的IPv6分片重组策略。


## 八、IP协议安全基线检查清单

| 检查项 | 基线标准 | 验证方法 |
|:---|:---|:---|
| uRPF（防IP欺骗） | 根据路由模式选择strict或loose | Linux: `sysctl net.ipv4.conf.all.rp_filter` |
| IP选项丢弃 | 边界丢弃带源路由等选项的包 | Cisco: `show running-config \| include ip options`；Linux: `sysctl net.ipv4.conf.all.accept_source_route` |
| 分片重组启用 | 防火墙强制虚拟重组 | 检查防火墙配置（Cisco ASA `fragment chain`） |
| TTL初始值 | 考虑自定义防指纹泄露 | `net.ipv4.ip_default_ttl=255`（可配置，但需不影响网络排障） |
| IPv6分片策略 | 启用IPv6分片重组及速率限制 | 检查防火墙IPv6分片配置 |


## 九、总结

IP协议是网络层的中枢，其无连接、尽力而为的设计使得上层协议必须自行保障可靠性。从攻防视角看，IP分片机制、TTL操纵、源地址伪造是攻击者的核心工具；uRPF、强制分片重组、IP选项丢弃是防御者的关键手段。

**核心认知更新**：
- **TTL指纹**在现代网络中已不可靠，不应作为OS判定的主要依据；
- **NAT-T（RFC 3948）** 使ESP模式IPsec可以正常穿越NAT，AH模式除外；
- **uRPF严格模式**需在对称路由网络中部署，非对称网络应使用松散模式。

掌握本文内容后，建议读者将IP知识与ICMP、ARP、路由协议串联，构建完整的网络层攻防知识体系。


## 参考文献与延伸阅读

### 标准与RFC
- RFC 791 — *Internet Protocol*（1981），J. Postel
- RFC 8200 — *Internet Protocol, Version 6 (IPv6) Specification*（2017），S. Deering, R. Hinden
- RFC 3948 — *UDP Encapsulation of IPsec ESP Packets*（2005），A. Huttunen et al.（NAT穿越标准）
- RFC 8899 — *Packetization Layer Path MTU Discovery*（2020），G. Fairhurst et al.（PLPMTUD）
- BCP 38 / RFC 2827 — *Network Ingress Filtering*（uRPF基础）

### 工程文档与框架
- Cisco IOS IP Addressing Configuration Guide — uRPF配置
- Linux内核文档 — `Documentation/networking/ip-sysctl.txt`
- MITRE ATT&CK — [T1498: Network Denial of Service](https://attack.mitre.org/techniques/T1498/)，[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/)

---

*本文修订于2026年8月，基于Ubuntu 22.04.3 LTS / Cisco IOS 15.9(3)M环境验证。IP行为因操作系统及防火墙实现存在差异，生产环境中请以具体设备文档为准。*
