# TCP协议深度解析：从三次握手原理到内网渗透攻击实战

> **实验环境**：Ubuntu 22.04 LTS（内核5.15）/ Kali Linux 2025.1 / Windows 11 22H2 / Wireshark 4.2.6 / Nginx 1.18.0
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。

## 一、TCP的核心矛盾与职责

- **定义**：TCP（传输控制协议，RFC 793）是传输层面向连接的、可靠的、基于**字节流**的协议。
- **底层矛盾**：TCP依赖的IP层提供“Best-Effort（尽力而为）”服务——不保证送达、顺序、不重复。
- **TCP的职责**：作为IP层的“快递理赔专员”，TCP必须解决三个核心问题：
  1. **连接建立**：确认双方存活且愿意通信。
  2. **可靠性保障**：确认数据送达，实现重传。
  3. **速率控制**：协调网络拥塞与接收方处理能力（流量控制 + 拥塞控制）。

## 二、TCP报文头部结构（灵魂在于“编号”）

TCP是“流”协议——它将应用层数据切成字节，给每个字节分配一个**序列号**，实现精确定位。

### 必须死磕的核心字段

| 字段 | 大小 | 含义 | 攻防意义 |
| :--- | :---: | :--- | :--- |
| **Sequence Number（SEQ）** | 32位 | 本报文段第一个字节的编号 | 可预测性导致会话劫持（ISN随机化是关键防御） |
| **Acknowledgment Number（ACK）** | 32位 | 期待对方下次发来的第一个字节编号（累积确认） | 判断丢包、重传、SACK的基准 |
| **Flags** | 9位 | SYN/ACK/FIN/RST等连接状态控制 | SYN Flood、RST攻击的核心目标 |
| **Window Size** | 16位 | 接收方可用缓冲区大小（流量控制） | 通过Window Scale扩展至1GB，可被利用于隐蔽传输 |
| **Checksum** | 16位 | 覆盖伪头部（含IP）+TCP头+数据 | NAT修改IP后必须重算，是CPU消耗主因 |

**Wireshark抓包冷知识**：你看到的 `Seq=0, Ack=0` 是**相对值**。实际线上传输的是32位随机绝对值，现代OS已实现RFC 1948的ISN随机化，防止攻击者预测。

## 三、连接建立（三次握手）——为什么必须是三次？

三次握手的本质是**双向序列号同步 + 资源预留验证**。

### 为什么必须是三次（防止历史连接）
若为两次握手：服务端收到旧SYN即分配全连接资源并进入ESTABLISHED。客户端收到SYN+ACK后发现Ack值不匹配，发送RST断连，服务端资源空耗。
**三次握手**下，服务端在半连接队列（SYN Queue）等待第三次ACK才分配全连接资源。若ACK未到，半连接在超时后回收。

## 四、可靠性传输与窗口机制

### 4.1 流量控制（接收方主导）
接收方在ACK中携带`Window Size`告知发送方“我还能收多少字节”。若窗口为0，发送方停止发送并周期发送**零窗口探测包**询问窗口是否恢复。

### 4.2 拥塞控制基础（发送方主导）
发送方自行维护**拥塞窗口（cwnd）**。最终发送窗口 = min(接收方通告窗口, 发送方cwnd)。
- **慢启动**：从初始cwnd（通常10 MSS）指数增长至`ssthresh`。
- **拥塞避免**：达到`ssthresh`后线性增长（每RTT +1 MSS）。
- **快速重传**：收到3个重复ACK立即重传丢失包。

### 4.3 拥塞控制现代演进
**CUBIC（Linux内核默认）**：在拥塞避免阶段改用**三次函数**模型增长。标准公式为 `W(t) = C × (t - K)³ + W_max`。丢包后，cwnd回退至 `W_max × β`（β=0.7），沿三次曲线向`W_max`增长，接近时增速放缓，在高带宽长延迟网络中性能远优于Reno。

**BBR（Google开发）**：不再依赖丢包作为拥塞信号，通过交替探测瓶颈带宽和最小RTT，保持**在途数据≈BDP（带宽-延迟积）**，使瓶颈链路排队延迟最小。

### 4.4 超时重传（RTO）与SACK
TCP估算平滑RTT（SRTT）和偏差（RTTVAR），`RTO = SRTT + 4×RTTVAR`（RFC 6298）。**SACK（RFC 2018）** 允许接收方明确告知已接收字节范围，使发送方只重传缺失段，减少冗余。

## 五、连接关闭（四次挥手）与 TIME_WAIT

### 为什么主动方必须等2MSL？
最后一次ACK可能丢失，被动方会重发FIN。2MSL确保本次连接所有报文在网络中消失。**注**：RFC 793规定MSL为2分钟（2MSL=4分钟），但**Linux内核硬编码`TCP_TIMEWAIT_LEN`为60秒**，生产环境调优需以此为基准。

### 生产环境调优（高并发短连接服务器）
```bash
# 查看当前TIME_WAIT数量
ss -tan state time-wait | wc -l

# sysctl调优（Ubuntu 22.04内核5.15）
net.ipv4.tcp_tw_reuse = 1           # TIME_WAIT socket重用于新出站连接
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_tw_buckets = 5000   # 超过后立即销毁（慎用）
```

## 六、红队/渗透测试视角：TCP的六大攻击面

### 1. SYN Flood（拒绝服务）
- **原理**：发送大量SYN包不发ACK，耗尽半连接队列。
- **防御**：`net.ipv4.tcp_syncookies = 1`。服务端不分配半连接表项，将信息编码为SYN+ACK的seq号。**注意**：SYN Cookie模式下，窗口缩放、SACK和TCP Fast Open选项通常被禁用（编码空间有限），高带宽场景性能下降。

### 2. TCP RST攻击（会话中断）
- **原理**：攻击者嗅探五元组，猜中序列号范围，伪造RST包强制断连。
- **防御**：① **TCP-AO（RFC 5925）** 密码学签名；② **RFC 5961（Challenge ACK）**——Linux内核3.6+默认启用，收到疑似RST时不立即断连，而是发送Challenge ACK要求对方确认序列号，极大增加了盲注攻击难度；③ 内网DAI阻断ARP欺骗切断嗅探前提。*(注：`tcp_rfc1337`主要保护TIME-WAIT状态，不直接防盲注RST)*。

### 3. TCP会话劫持
若ISN可预测，攻击者可伪造ACK注入数据。现代OS采用RFC 1948 ISN随机化（随机偏移+杂凑），预测几乎不可能。

### 4. 端口扫描（内网横向探测）
- **SYN扫描 (`-sS`)**：发SYN，收SYN+ACK即RST。快速且隐蔽（推荐）。
- **FIN/Xmas扫描 (`-sF`/`-sX`)**：关闭端口必回RST，开放端口静默。**注意**：此方法对现代Windows系统无效（Windows TCP栈不论端口状态均丢弃无标志位包），仅适用于Unix-like系统探测。

### 5. 窗口缩放利用 + 零窗口探测隐蔽信道
- **Window Scale**：将16位窗口扩展至最高1GB。NDR设备若未解析此选项，会低估实际传输量，导致数据外泄告警绕过。
- **零窗口探测隐蔽信道**：被控主机向C2发送看似正常的“零窗口探测”包，C2在ACK中通过`Window Size`的微小变化携带指令，在传统防火墙上极难被识别。

### 6. SACK漏洞引发的内核DoS
- **CVE-2018-5390（SegmentSmack）**：利用精心构造的SACK块，导致内核在处理乱序队列时触发**算法复杂性漏洞**，引发CPU软中断死锁（非内存溢出）。
- **CVE-2019-11477（SACK Panic）**：在`tcp_fragment`函数中因MSS计算触发**整数溢出**，导致kernel panic。
- **防御**：应用安全更新（kernel ≥ 4.15.2 / 4.14.19），或临时禁用SACK（`net.ipv4.tcp_sack = 0`，严重影响重传性能）。

## 七、TCP状态机与防火墙检测联动

状态防火墙跟踪TCP状态机，若收到非对称包（如ESTABLISHED状态收到SYN），视为非法并丢弃。攻击者可利用**分片绕过**或**非对称路由**导致防火墙状态表不一致。

```text
[状态机核心路径节选]
CLOSED -> (主动打开/SYN) -> SYN_SENT -> (收到SYN+ACK/发ACK) -> ESTABLISHED
LISTEN -> (收到SYN/发SYN+ACK) -> SYN_RCVD -> (收到ACK) -> ESTABLISHED
ESTABLISHED -> (主动关闭/FIN) -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT -> (2MSL) -> CLOSED
ESTABLISHED -> (被动关闭/收到FIN) -> CLOSE_WAIT -> (发FIN) -> LAST_ACK -> CLOSED
```

## 八、内网协议栈联动（实战映射）

> ⚠️ **风险提示**：以下穿透技术描述仅供理解协议封装机制，实际内网测试需严格遵守授权边界。

- **SMB横向移动（TCP 445）**：若防火墙仅允许80/443出站，可用SSH隧道或SOCKS代理将445映射到内网目标。
- **Kerberos（TCP/UDP 88）**：Wireshark过滤`tcp.port == 88`，`Follow TCP Stream`可提取AS-REP/TGS-REP加密票据。
- **RDP（TCP 3389）**：CredSSP（NLA）在TCP握手后直接嵌套TLS，在TLS隧道内封装SPNEGO（Kerberos/NTLM）进行预认证。Wireshark无法直接解密TLS内的哈希，需提取外层NTLM Type消息离线爆破。

## 九、TCP协议安全基线检查清单

| 检查项 | 基线标准（Linux内核5.x） | 验证命令 |
|:---|:---|:---|
| SYN Cookie | 启用（半连接队列溢出时自动生效） | `sysctl net.ipv4.tcp_syncookies` |
| TIME_WAIT复用 | 仅出站启用（`tcp_tw_reuse=1`） | `sysctl net.ipv4.tcp_tw_reuse` |
| RFC 5961 | 启用（防盲注RST/数据注入） | `sysctl net.ipv4.tcp_challenge_ack_limit` |
| 半连接队列 | `tcp_max_syn_backlog ≥ 4096` | `sysctl net.ipv4.tcp_max_syn_backlog` |
| TCP-AO | 关键连接（如BGP）启用 | 应用层配置验证 |

## 十、避坑指南与排障经验

### 坑1：Ping通但TCP连不上
防火墙禁止目标TCP端口，但放行ICMP。验证：`telnet IP 80` 或 `nmap -p 80 IP`。

### 坑2：连接建立后频繁断线
防火墙状态表超时（某些防火墙默认60分钟，长连接超时后发RST）。NAT网关`nf_conntrack_max`耗尽导致丢包。

### 坑3：TIME_WAIT导致端口耗尽
现象：`Cannot assign requested address`。解决：启用`tcp_tw_reuse` + Nginx长连接配置。

### 坑4：TCP校验和错误（Wireshark显示incorrect）
根因：网卡**校验和卸载**。抓包点在驱动层（硬件计算前）。验证：`ethtool -k eth0 | grep checksum`。不影响通信，网卡在发送前最后一刻计算正确校验和。

## 十一、参考资料

1. **RFC 793** — *Transmission Control Protocol*
2. **RFC 5961** — *Improving TCP's Robustness to Blind In-Window Attacks*
3. **RFC 8312** — *CUBIC for Fast Long-Distance Networks*
4. **CVE-2019-11477** — *SACK Panic Integer Overflow*
5. **MITRE ATT&CK** — *T1046 (Network Service Scanning)*, *T1572 (Protocol Tunneling)*

---

**总结**：TCP是现代网络通信的“毛细血管”，也是几乎所有内网攻击流量的传输底座。其核心在于**序列号机制**、**窗口管理**和**连接状态机**。SYN Flood、RST攻击、会话劫持、隐蔽信道构成TCP的主要攻击面；SYN Cookie、RFC 5961 Challenge ACK、ISN随机化构成防御纵深。掌握本文内容后，建议读者将TCP与ARP、IP、ICMP串联，构建完整的网络层-传输层攻防知识体系。

---

*本文修订于2026年8月，基于Ubuntu 22.04 LTS（内核5.15）/ Cisco IOS 15.2环境验证。TCP行为因操作系统及内核版本存在差异，生产环境中请以具体设备文档为准。*
