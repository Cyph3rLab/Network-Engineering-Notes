# TCP协议深度解析：从三次握手原理到内网渗透攻击实战

> **实验环境**：Ubuntu 22.04.3 LTS（内核5.15.0-91-generic）/ Kali Linux 2025.1 / Windows 11 22H2 / Wireshark 4.2.6 / Nginx 1.18.0
>
> **合规声明**：本文所有攻击技术描述**仅限用于网络安全防护研究与获得书面授权的隔离环境安全测试**。未经授权的SYN Flood、端口扫描、会话劫持等行为，违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条，切勿用于非法目的。


## 一、TCP的核心矛盾与职责

- **定义**：TCP（传输控制协议，RFC 793）是传输层面向连接的、可靠的、基于**字节流**的协议。
- **底层矛盾**：TCP依赖的IP层提供“Best-Effort（尽力而为）”服务——不保证送达、顺序、不重复。
- **TCP的职责**：作为IP层的“快递理赔专员”，TCP必须解决三个核心问题：
  1. **连接建立**：确认双方存活且愿意通信（三次握手）。
  2. **可靠性保障**：确认数据送达，实现重传（ACK+超时重传+SACK）。
  3. **速率控制**：协调网络拥塞与接收方处理能力（流量控制+拥塞控制）。


## 二、TCP报文头部结构（灵魂在于“编号”）

TCP是“流”协议——它将应用层数据切成字节，给每个字节分配一个**序列号**，实现精确定位。

### 必须死磕的核心字段

| 字段 | 大小 | 含义 | 攻防意义 |
|:---|:---:|:---|:---|
| **Sequence Number（SEQ）** | 32位 | 本报文段第一个字节的编号 | 可预测性导致会话劫持（ISN随机化是关键防御——RFC 1948/6528） |
| **Acknowledgment Number（ACK）** | 32位 | 期待对方下次发来的第一个字节编号（累积确认） | 判断丢包、重传、SACK的基准 |
| **Flags** | 9位 | SYN/ACK/FIN/RST等连接状态控制 | SYN Flood、RST攻击的核心目标 |
| **Window Size** | 16位 | 接收方可用缓冲区大小（流量控制） | 配合Window Scale（RFC 7323）可扩展至~1GB，可被利用于侧信道观测 |
| **Checksum** | 16位 | 覆盖伪头部（含IP）+TCP头+数据 | NAT修改IP/端口后必须重算，是CPU消耗主因 |

**Wireshark抓包冷知识**：你看到的 `Seq=0, Ack=0` 是**相对值**（Wireshark默认启用`seq/ack`相对化）。实际线上传输的是32位随机绝对值，现代OS已实现ISN随机化，防止攻击者预测。


## 三、连接建立（三次握手）——为什么必须是三次？

三次握手的本质是**双向序列号同步 + 资源预留验证**。

**为什么必须是三次（防止历史连接）** ：
若为两次握手：服务端收到旧SYN即分配全连接资源并进入ESTABLISHED。客户端收到SYN+ACK后发现Ack值不匹配，发送RST断连，服务端资源空耗。

**三次握手**下，服务端在半连接队列（SYN Queue）等待第三次ACK才分配全连接资源（进入ACCEPT队列）。若ACK未到，半连接在超时后回收。


## 四、可靠性传输与窗口机制

### 4.1 流量控制（接收方主导）

接收方在ACK中携带`Window Size`告知发送方“我还能收多少字节”。若窗口为0，发送方停止发送并周期发送**零窗口探测包**（Zero Window Probe，间隔RTO，通常数秒一次）询问窗口是否恢复——这是**TCP协议的流量控制标准机制**，本身并非隐蔽信道。

> **⚠️ 澄清**：零窗口探测是TCP的标准流量控制机制，**不是攻击技术**。攻击者若希望利用TCP的窗口字段传递隐蔽数据，应使用**TCP选项隐蔽信道**（如Timestamp选项中的TSval字段LSB位编码）或**序列号偏差隐蔽信道**，而非零窗口探测。

### 4.2 拥塞控制（发送方主导）

发送方自行维护**拥塞窗口（cwnd）**。最终发送窗口 = min(接收方通告窗口, 发送方cwnd)。

- **慢启动**：从初始cwnd（RFC 6928推荐10 MSS）指数增长至`ssthresh`。
- **拥塞避免**：达到`ssthresh`后线性增长（每RTT +1 MSS）。
- **快速重传**：收到3个重复ACK立即重传丢失包。
- **快速恢复**：重传后进入快速恢复而非慢启动。

**CUBIC（Linux内核5.x默认）** ：CUBIC的拥塞避免阶段采用**三次多项式窗口增长函数**：

`W(t) = C × (t - K)³ + W_max`

其中：
- `W_max` = 丢包发生时的窗口大小；
- `C` = 缩放常数（默认0.4），控制曲线陡峭度；
- `K` = 从当前窗口恢复到`W_max`所需的理论时间，由 `K = ³√(W_max × (1 - β) / C)` 计算得出（`β`=0.7）。

**核心行为**：丢包后cwnd回退至`W_max × β`，沿三次曲线向`W_max`增长。接近`W_max`时增速放缓（避免过度冲击网络），若继续增长则平滑超越。这一设计避免了Reno线性增长的锯齿效应，在高带宽长延迟网络中性能显著优于Reno（RFC 8312）。

**BBR（Google开发）** ：不再依赖丢包作为拥塞信号，通过交替探测瓶颈带宽和最小RTT，保持在途数据≈BDP（带宽-延迟积），使排队延迟最小。

### 4.3 超时重传（RTO）与SACK

TCP估算平滑RTT（SRTT）和偏差（RTTVAR），`RTO = SRTT + 4 × RTTVAR`（RFC 6298）。**SACK（RFC 2018）** 允许接收方明确告知已接收字节范围，使发送方只重传缺失段，减少冗余。


## 五、连接关闭（四次挥手）与TIME_WAIT

### 为什么主动方必须等2MSL？

最后一次ACK可能丢失，被动方会重发FIN。2MSL确保本次连接所有报文在网络中消失。RFC 793建议MSL=2分钟（2MSL=4分钟），但**Linux内核硬编码`TCP_TIMEWAIT_LEN`为60秒**，生产环境调优需以此为基准。

### 生产环境调优（高并发短连接服务器）
```bash
# 查看当前TIME_WAIT数量（兼容ss各版本）
ss -tan | grep -c TIME-WAIT

# sysctl调优（Ubuntu 22.04内核5.15）
net.ipv4.tcp_tw_reuse = 1           # TIME_WAIT socket重用于新出站连接
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_tw_buckets = 5000   # 超过后立即销毁（慎用，可能破坏协议语义）
```


## 六、红队/渗透测试视角：TCP的六大攻击面

### 6.1 攻击面1：SYN Flood（拒绝服务）

- **原理**：发送大量SYN包不发ACK，耗尽半连接队列（`tcp_max_syn_backlog`）。
- **防御**：`net.ipv4.tcp_syncookies = 1`。服务端不分配半连接表项，将连接信息编码为SYN+ACK的seq号。
- **现代内核（4.9+）演进**：SYN Cookie通过协同TCP Timestamp选项编码，已实现对**Window Scaling的有限支持**，但SACK和TFO仍可能受限（取决于内核版本）。**高吞吐场景建议同时调大半连接队列**（`net.core.somaxconn`和`tcp_max_syn_backlog`）以降低对SYN Cookie的性能依赖。

### 6.2 攻击面2：TCP RST攻击（会话中断）

- **原理**：攻击者嗅探五元组，猜中序列号范围，伪造RST包强制断连（前提：已获内网嗅探能力）。
- **防御纵深**：
  - **TCP-AO（RFC 5925）** ：密码学签名保护（适用于BGP等关键TCP连接，部署成本高）；
  - **RFC 5961 Challenge ACK（Linux内核3.6+默认启用）** ：收到疑似非法RST/数据包时，发送Challenge ACK要求对方确认序列号（`net.ipv4.tcp_challenge_ack_limit=100`控制速率）；
  - **RFC 1337 TIME-WAIT保护（`net.ipv4.tcp_rfc1337=1`）** ：保护TIME-WAIT状态的连接免遭RST终止（与RFC 5961是两套独立机制）；
  - **内网DAI**阻断ARP欺骗切断嗅探前提。

### 6.3 攻击面3：TCP会话劫持（ISN预测）

若ISN可预测，攻击者可伪造ACK注入数据。现代OS采用RFC 1948/6528 ISN随机化（随机偏移+时间戳杂凑），预测几乎不可能。

### 6.4 攻击面4：端口扫描（内网横向探测）

- **SYN扫描（`-sS`）** ：发SYN，收SYN+ACK即RST。快速且隐蔽（推荐）。
- **FIN/Xmas扫描（`-sF`/`-sX`）** ：关闭端口必回RST，开放端口静默。**注意**：此方法对现代Windows系统无效，仅适用于Unix-like系统探测。

### 6.5 攻击面5：TCP选项隐蔽信道

攻击者可将数据编码在TCP Timestamp选项（TSval字段的LSB位）或TCP序列号的特定偏差中，在合规流量中夹带指令。检测上需关注Timestamps字段的熵值异常或序列号偏差的统计异常（需NDR设备支持）。

### 6.6 攻击面6：SACK漏洞引发的内核DoS

| CVE | 原理 | 修复版本（Ubuntu） |
|:---|:---|:---|
| **CVE-2018-5390（SegmentSmack）** | 利用精心构造的SACK块，触发内核**算法复杂性漏洞**（CPU软中断死锁） | Ubuntu 18.04: 4.15.0-34-generic+ |
| **CVE-2019-11477（SACK Panic）** | 在`tcp_fragment`函数中因特定MSS值（约48字节）和SACK块组合触发**整数溢出**，导致kernel panic | Ubuntu 18.04: 4.15.0-52-generic+ |

**检测与缓解**：
```bash
# 检查当前内核版本
uname -r
# 临时缓解（严重影响重传性能，仅限紧急情况）
sysctl -w net.ipv4.tcp_sack=0
```


## 七、TCP状态机与防火墙检测联动

状态防火墙跟踪TCP状态机，若收到非对称包（如ESTABLISHED状态收到SYN），视为非法并丢弃。攻击者可利用**分片绕过**或**非对称路由**导致防火墙状态表不一致。

```text
[状态机核心路径节选]
CLOSED -> (主动打开/SYN) -> SYN_SENT -> (收到SYN+ACK/发ACK) -> ESTABLISHED
LISTEN -> (收到SYN/发SYN+ACK) -> SYN_RCVD -> (收到ACK) -> ESTABLISHED
ESTABLISHED -> (主动关闭/FIN) -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT -> (2MSL) -> CLOSED
ESTABLISHED -> (被动关闭/收到FIN) -> CLOSE_WAIT -> (发FIN) -> LAST_ACK -> CLOSED
```


## 八、内网协议栈联动（红队实战映射）

> **⚠️ 风险提示**：以下渗透技术描述仅供理解协议封装机制，实际内网测试需严格遵守授权边界。

- **SMB横向移动（TCP 445）** ：若防火墙仅允许80/443出站，可用SSH隧道或SOCKS代理将445映射到内网目标。
- **Kerberos（TCP/UDP 88）** ：Wireshark可过滤`tcp.port == 88`，但**票据（Ticket）和认证数据均为加密字段**，需拥有目标服务密钥（keytab）才能解密。红队场景中通过**mimikatz/Rubeus**从内存提取票据（TGT/TGS）进行Pass-the-Ticket攻击。
- **RDP（TCP 3389）** ：CredSSP（NLA）在TCP握手后直接嵌套TLS，在TLS隧道内封装SPNEGO（Kerberos/NTLM）进行预认证。Wireshark无法直接解密TLS内的哈希，需提取外层NTLM Type消息离线爆破。


## 九、TCP协议安全基线检查清单

| 检查项 | 基线标准（Linux内核5.x） | 验证命令 |
|:---|:---|:---|
| SYN Cookie | 启用（半连接队列溢出时自动生效） | `sysctl net.ipv4.tcp_syncookies` |
| 半连接队列 | `tcp_max_syn_backlog ≥ 4096` | `sysctl net.ipv4.tcp_max_syn_backlog` |
| TIME_WAIT复用 | 仅出站启用（`tcp_tw_reuse=1`） | `sysctl net.ipv4.tcp_tw_reuse` |
| RFC 5961 Challenge ACK | 启用（防盲注RST/数据注入） | `sysctl net.ipv4.tcp_challenge_ack_limit`（默认100） |
| RFC 1337 TIME-WAIT保护 | 启用 | `sysctl net.ipv4.tcp_rfc1337` |
| TIME-WAIT回收 | **禁用**（`tcp_tw_recycle`已在4.12+移除） | `sysctl net.ipv4.tcp_tw_recycle`（应返回0或不存在） |
| SACK补丁 | 已打最新补丁 | `uname -r` 对照CVE公告 |


## 十、避坑指南与排障经验

### 坑1：Ping通但TCP连不上
防火墙禁止目标TCP端口，但放行ICMP。验证：`telnet <IP> 80` 或 `nmap -p 80 <IP>`。

### 坑2：连接建立后频繁断线
防火墙状态表超时（某些防火墙默认60分钟，长连接超时后发RST）。NAT网关`nf_conntrack_max`耗尽导致丢包。

### 坑3：TIME_WAIT导致端口耗尽
现象：`Cannot assign requested address`。解决：启用`tcp_tw_reuse` + Nginx长连接配置 + 调大本地端口范围。

### 坑4：TCP校验和错误（Wireshark显示incorrect）
根因：网卡**校验和卸载**（Tx Checksum Offload）。抓包点在驱动层（硬件计算前）。验证：`ethtool -k eth0 | grep checksum`。不影响通信，网卡在发送前最后一刻计算正确校验和。


## 十一、参考资料

1. **RFC 793** — *Transmission Control Protocol*（1981），J. Postel
2. **RFC 1948** — *Defending Against Sequence Number Attacks*（1996），S. Bellovin
3. **RFC 5961** — *Improving TCP's Robustness to Blind In-Window Attacks*（2010），A. Ramaiah et al.
4. **RFC 6298** — *Computing TCP's Retransmission Timer*（2011），V. Paxson et al.
5. **RFC 8312** — *CUBIC for Fast Long-Distance Networks*（2018），I. Rhee et al.
6. **RFC 6528** — *Defending against Sequence Number Attacks*（2012），S. Bellovin et al.
7. **MITRE ATT&CK** — [T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/)，[T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)


**总结**：TCP是现代网络通信的“毛细血管”，也是几乎所有内网攻击流量的传输底座。其核心在于**序列号机制**、**窗口管理**和**连接状态机**。SYN Flood、RST攻击、会话劫持、SACK漏洞、TCP选项隐蔽信道构成TCP的主要攻击面；SYN Cookie、RFC 5961 Challenge ACK、ISN随机化、TCP-AO构成防御纵深。**注意区分**：零窗口探测是TCP流量控制的标准机制，并非隐蔽信道技术；真正的TCP隐蔽信道利用Timestamps或序列号偏差承载数据。

掌握本文内容后，建议读者将TCP与ARP、IP、ICMP串联，构建完整的网络层-传输层攻防知识体系。

---

*本文修订于2026年8月，基于Ubuntu 22.04.3 LTS（内核5.15.0-91-generic）/ Windows 11 22H2环境验证。TCP行为因操作系统及内核版本存在差异，生产环境中请以具体设备文档为准。*
