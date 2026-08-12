# TCP协议深度解析：从三次握手原理到内网渗透攻击实战

> **实验环境**：Ubuntu 22.04 LTS（内核5.15）/ Kali Linux 2025.1 / Windows 11 22H2 / Wireshark 4.2.6 / Nginx 1.18.0
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。


## 一、TCP的核心矛盾与职责

- **定义**：TCP（传输控制协议，RFC 793）是传输层面向连接的、可靠的、基于**字节流**的协议。
- **底层矛盾**：TCP依赖的IP层提供 **“Best-Effort（尽力而为）”** 服务——不保证送达、顺序、不重复。
- **TCP的职责**：作为IP层的“快递理赔专员”，TCP必须解决三个核心问题：
  1. **连接建立**：确认双方存活且愿意通信。
  2. **可靠性保障**：确认数据送达，实现重传。
  3. **速率控制**：协调网络拥塞与接收方处理能力（流量控制 + 拥塞控制）。


## 二、TCP报文头部结构（灵魂在于“编号”）

TCP是**“流”协议**——它将应用层数据切成字节，给每个字节分配一个**序列号**，实现精确定位。

### 必须死磕的核心字段

| 字段 | 大小 | 含义 | 攻防意义 |
| :--- | :---: | :--- | :--- |
| **Sequence Number（SEQ）** | 32位 | 本报文段**第一个字节**的编号（非“第几个包”） | 可预测性导致会话劫持（ISN随机化是关键防御） |
| **Acknowledgment Number（ACK）** | 32位 | “我期待你下次发来的第一个字节编号”（累积确认） | 判断丢包、重传、SACK的基准 |
| **Flags** | 9位 | SYN/ACK/FIN/RST等连接状态控制 | SYN Flood、RST攻击的核心目标 |
| **Window Size** | 16位 | 接收方可用缓冲区大小（流量控制） | 通过RFC 1323窗口缩放扩展至1GB，可被利用于高速隐蔽传输 |
| **Checksum** | 16位 | 覆盖伪头部（含IP）+TCP头+数据 | NAT修改IP后必须重算，是CPU消耗主因 |

**Wireshark抓包冷知识**：你看到的 `Seq=0, Ack=0` 是**相对值**（Relative Sequence），这是Wireshark为方便阅读计算的偏移量。实际线上传输的是**32位随机绝对值**——现代OS已实现RFC 1948的ISN随机化，防止攻击者预测。

### TCP选项字段（攻防关键）

| 选项 | 类型号 | 功能 | 安全/工程关联 |
|:---|:---:|:---|:---|
| **MSS** | 2 | 协商最大分段大小（MTU-40/60） | 路径MTU探测基础 |
| **Window Scale** | 3 | 窗口左移位数（RFC 1323） | 实际窗口=窗口值 << 左移位数，最大达1GB |
| **SACK** | 4/5 | 选择性确认（RFC 2018） | 精确告知已接收字节范围，减少重传浪费 |
| **Timestamp** | 8 | 精确RTT测量+防序列号回绕（PAWS，RFC 7323） | 高带宽网络必备 |


## 三、连接建立（三次握手）——为什么必须是三次？

三次握手的本质是**双向序列号同步 + 资源预留验证**。

### 握手流程

| 步骤 | 方向 | 报文内容 | 状态迁移 |
|:---:|:---|:---|:---|
| ① | 客户端→服务端 | SYN, Seq=x | CLOSED→**SYN_SENT** |
| ② | 服务端→客户端 | SYN+ACK, Seq=y, Ack=x+1 | LISTEN→**SYN_RCVD** |
| ③ | 客户端→服务端 | ACK, Ack=y+1 | **ESTABLISHED**（双方） |

### 为什么必须是三次（防止历史连接 + 资源预留验证）

**核心逻辑**：服务端仅凭客户端的SYN分配全连接资源（内存TCB，~256-300字节）存在风险。第三次ACK的作用是**确认客户端确实收到了服务端的SYN+ACK**，从而验证客户端的接收能力。

**历史连接场景**：客户端发送了seq=100的SYN（网络拥堵），超时后重发seq=200的SYN。旧SYN（seq=100）绕路后晚到。若为**两次握手**，服务端收到旧SYN即分配资源并进入ESTABLISHED；客户端收到SYN+ACK后发现ACK值不匹配自己期望的ACK（期望Ack=201），发送RST断连，服务端资源空耗。**三次握手**下，服务端在半连接队列（SYN Queue）等待第三次ACK才分配全连接资源，若第三次ACK未到，半连接条目在超时（通常75秒）后回收。


## 四、可靠性传输与窗口机制

### 4.1 流量控制（Flow Control，接收方主导）

接收方在每次ACK中携带`Window Size`字段，告知发送方“我还能收多少字节”。发送方需确保**在途数据（已发未确认）≤ 接收方通告窗口**。

**零窗口（Zero Window）** ：若窗口为0，发送方停止发送，并周期发送**零窗口探测包（1字节数据）** 询问窗口是否恢复（RFC 793）。

### 4.2 拥塞控制基础（发送方主导）

发送方自行维护**拥塞窗口（cwnd）** ，根据网络状况调整。**最终发送窗口 = min(接收方通告窗口, 发送方cwnd)**。

**慢启动（Slow Start）** ：从初始cwnd（通常10 MSS，RFC 6928）指数增长至`ssthresh`（慢启动阈值）。
**拥塞避免**：达到`ssthresh`后线性增长（每RTT +1 MSS）。
**快速重传**：收到**3个重复ACK**立即重传丢失包，不等待超时。
**快速恢复（Fast Recovery）** ：重传后，`ssthresh = cwnd/2`，`cwnd = ssthresh + 3×MSS`，进入拥塞避免。

### 4.3 拥塞控制现代演进

**CUBIC（Linux内核默认）** ：保留慢启动阶段（指数增长至`ssthresh`），但在**拥塞避免阶段**改用**三次函数**（`cwnd = W_max - C × (t - K)³`）替代线性增长。丢包后，cwnd回退至 `W_max × β`（β=0.7，乘性减少因子），沿三次曲线向`W_max`增长，接近时增速放缓。在高带宽长延迟网络中性能远优于Reno。

**BBR（Google开发）** ：不再依赖丢包作为拥塞信号，通过**交替探测瓶颈带宽和最小RTT**调节`pacing_gain`和`cwnd_gain`，目标是保持**在途数据≈BDP（带宽-延迟积）**，使瓶颈链路排队延迟最小。已部署于YouTube和Google骨干网。

### 4.4 超时重传（RTO）与SACK

TCP估算平滑RTT（SRTT）和偏差（RTTVAR），`RTO = SRTT + 4×RTTVAR`（RFC 6298）。**SACK（RFC 2018）** 允许接收方在ACK中明确告知“我已收到字节范围1000-1499和2000-2499”，使发送方只重传缺失段（1500-1999），减少冗余。


## 五、连接关闭（四次挥手）与 TIME_WAIT

| 步骤 | 方向 | 报文 | 状态迁移 |
|:---:|:---|:---|:---|
| ① | 主动方→被动方 | FIN | **FIN_WAIT_1** |
| ② | 被动方→主动方 | ACK | **FIN_WAIT_2**（主动方）/ **CLOSE_WAIT**（被动方） |
| ③ | 被动方→主动方 | FIN | **LAST_ACK**（被动方） |
| ④ | 主动方→被动方 | ACK | **TIME_WAIT**（主动方，持续2MSL→CLOSED） |

### 为什么主动方必须等2MSL（RFC 793 §3.5）？

最后一次ACK可能丢失，被动方会重发FIN。若主动方直接关闭，就收不到重发FIN，被动方永远卡在`LAST_ACK`。**2MSL（Maximum Segment Lifetime × 2，Linux默认60秒）** 确保本次连接所有报文在网络中消失，才能安全关闭。

### 生产环境调优（高并发短连接服务器）

```bash
# 查看当前TIME_WAIT数量
ss -tan state time-wait | wc -l

# sysctl调优（Ubuntu 22.04内核5.15）
net.ipv4.tcp_tw_reuse = 1           # TIME_WAIT socket重用于新出站连接
# net.ipv4.tcp_tw_recycle = 0       # 内核4.12起已移除，无需配置
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_tw_buckets = 5000   # 超过后立即销毁（暴力手段，慎用）

# 配合Nginx长连接配置（减少短连接）
keepalive_requests 1000;
keepalive_timeout 65s;
```


## 六、红队/渗透测试视角：TCP的六大攻击面

### 1. SYN Flood（拒绝服务）

- **原理**：攻击者发送大量SYN包，不发第三次ACK，耗尽服务端半连接队列（`net.ipv4.tcp_max_syn_backlog`，默认1024）。
- **防御**：`net.ipv4.tcp_syncookies = 1`（SYN Cookie）。服务端不分配半连接表项，将连接信息编码为SYN+ACK的seq号，仅当收到合法ACK（seq+1）时才建立全连接。**注意**：SYN Cookie模式下窗口缩放和SACK选项通常被禁用（编码空间有限），高带宽场景性能下降。

### 2. TCP RST攻击（会话中断）

- **原理**：攻击者嗅探连接五元组，猜中当前序列号范围，伪造RST包强制断连。
- **防御**：① **TCP-AO（RFC 5925）** ——密码学签名（需两端支持）；② Linux `net.ipv4.tcp_rfc1337 = 1`（严格RFC 1337，降低窗口内序列号被猜中概率）；③ 内网DAI+802.1X阻断ARP欺骗，切断嗅探前提。

### 3. TCP会话劫持（Sequence Prediction）

- **原理**：若ISN可预测（旧Windows系统），攻击者可伪造ACK注入恶意数据。
- **现代防御**：RFC 1948 ISN随机化（Linux采用随机偏移 + 时间戳杂凑），预测几乎不可能。

### 4. 端口扫描（内网横向探测）

| 类型 | Nmap参数 | 原理 | 优缺点 |
|:---|:---|:---|:---|
| SYN扫描 | `-sS` | 发SYN，收SYN+ACK即RST | 快、隐蔽（推荐） |
| Connect扫描 | `-sT` | 完整三次握手再断开 | 准确但易被记录 |
| FIN扫描 | `-sF` | 关闭端口必回RST，开放端口静默 | 绕过无状态防火墙 |
| NULL/Xmas | `-sN`/`-sX` | 同FIN | 同上 |

### 5. 窗口缩放利用 + 零窗口探测隐蔽信道（高级）

- **Window Scale（RFC 1323）** ：将16位窗口扩展至最高1GB，在少数ACK中传输大量数据。NDR设备若未解析Window Scale选项，会低估实际传输量，导致数据外泄告警绕过。
- **零窗口探测隐蔽信道**：被控主机向C2发送看似正常的“零窗口探测”包，C2在ACK中通过`Window Size`的微小变化携带指令，在传统防火墙上极难被识别。

### 6. SACK Panic（CVE-2018-5390）

- **原理**：攻击者构造带有精心排序的SACK块的分段，触发Linux内核`tcp_fragment`函数整数溢出，导致kernel panic。
- **防御**：应用安全更新（kernel ≥ 4.15.2 / 4.14.19），或禁用SACK（`net.ipv4.tcp_sack = 0`，会严重影响重传性能）。


## 七、TCP状态机与防火墙检测联动（快照）

```
          ┌────────┐
          │ CLOSED │
          └────┬───┘
               │ 被动打开
               ▼
          ┌────────┐
          │ LISTEN │
          └────┬───┘         主动打开（SYN）
               │ ① SYN  ─────────────┐
               ▼                      │
          ┌────────┐              ┌────────┐
          │SYN_RCVD│◀─────────────│SYN_SENT│
          └────┬───┘ ② SYN+ACK   └────────┘
               │ ③ ACK
               ▼
          ┌───────────┐
          │ESTABLISHED│
          └─────┬─────┘
                │ 主动关闭（FIN） ｜被动关闭（FIN）
                ▼                 ▼
          ┌──────────┐     ┌──────────┐
          │FIN_WAIT_1│     │CLOSE_WAIT│
          └────┬─────┘     └────┬─────┘
               │ ACK            │ 发FIN
               ▼                ▼
          ┌──────────┐     ┌──────────┐
          │FIN_WAIT_2│────▶│ LAST_ACK │
          └────┬─────┘  FIN└────┬─────┘
               │                │ ACK
               ▼                ▼
          ┌──────────┐     ┌──────────┐
          │ TIME_WAIT│     │  CLOSED  │
          └──────────┘     └──────────┘
               │ 2MSL后
               ▼
          ┌────────┐
          │ CLOSED │
          └────────┘
```

**防火墙状态检测**：状态防火墙跟踪TCP状态机，若收到非对称包（如ESTABLISHED状态收到SYN），视为非法并丢弃。攻击者可利用**分片绕过**或**非对称路由**导致防火墙状态表不一致，实现绕过。


## 八、内网协议栈联动（实战映射）

- **SMB横向移动（TCP 445）** ：若防火墙仅允许80/443出站，可用**SSH隧道**或**SOCKS代理**将445映射到内网目标。
- **Kerberos（TCP/UDP 88）** ：Wireshark过滤`tcp.port == 88`，`Follow TCP Stream`可提取加密TGT。
- **RDP（TCP 3389）** ：CredSSP（NLA）在TCP握手后嵌套TLS/SMB，Wireshark无法直接解析NTLM哈希，需配合`tshark`导出原始流后用`hashcat`离线破解。


## 九、TCP协议安全基线检查清单

| 检查项 | 基线标准（Linux内核5.x） | 验证命令 |
|:---|:---|:---|
| SYN Cookie | 启用（半连接队列溢出时自动生效） | `sysctl net.ipv4.tcp_syncookies` |
| TIME_WAIT复用 | 仅出站启用（`tcp_tw_reuse=1`） | `sysctl net.ipv4.tcp_tw_reuse` |
| 端口范围 | 1024-65535（或更高） | `sysctl net.ipv4.ip_local_port_range` |
| 半连接队列 | `tcp_max_syn_backlog ≥ 4096` | `sysctl net.ipv4.tcp_max_syn_backlog` |
| TCP Keep-Alive | 建议≤600秒 | `sysctl net.ipv4.tcp_keepalive_time` |
| SACK | 启用（性能）但补丁到最新 | `sysctl net.ipv4.tcp_sack`（1启用） |
| TCP-AO | 关键连接（如BGP）启用 | 应用层配置验证 |


## 十、避坑指南与排障经验

### 坑1：Ping通但TCP连不上
- **根因**：防火墙禁止目标TCP端口，但放行ICMP。
- **验证**：`telnet IP 80` 或 `nmap -p 80 IP`。

### 坑2：连接建立后频繁断线
- **检查1**：防火墙状态表超时（某些防火墙默认60分钟，长连接超时后发RST）。
- **检查2**：NAT网关`nf_conntrack_max`耗尽（`cat /proc/sys/net/netfilter/nf_conntrack_max`）。

### 坑3：TIME_WAIT导致端口耗尽
- **现象**：`Cannot assign requested address`。
- **解决方案**：第五节调优方案 + Nginx长连接配置。

### 坑4：TCP校验和错误（Wireshark显示incorrect）
- **根因**：网卡**校验和卸载（Checksum Offload）** （详见TCP文章4.5节）。
- **验证**：`ethtool -k eth0 | grep checksum`，抓包点在驱动层（卸载未完成）。
- **不影响通信**：网卡在发送前最后一刻计算正确校验和。


## 十一、TCP知识坐标系（与已学知识联动）

| 层级 | 协议 | 与TCP的关系 |
|:---|:---|:---|
| **链路层** | MAC/VLAN | 提供同一广播域内的帧传输，TCP的底层载体 |
| **网络层** | IP/ICMP/Routing | TCP依赖IP寻址，ICMP错误报告（如Frag Needed）影响TCP PMTUD |
| **传输层（本篇）** | TCP | 在IP不可靠之上建立可靠字节流 |
| **即将学习** | HTTP/SMB/Kerberos | TCP承载应用层协议，端口号标识服务 |


## 十二、参考资料

1. **RFC 793** — *Transmission Control Protocol*（TCP基础规范）
2. **RFC 1948** — *Defending Against Sequence Number Attacks*（ISN随机化）
3. **RFC 1323 / 7323** — *TCP Extensions for High Performance*（窗口缩放+时间戳）
4. **RFC 2018** — *TCP Selective Acknowledgment Options*（SACK）
5. **RFC 5681** — *TCP Congestion Control*（Reno/CUBIC基础）
6. **RFC 5925** — *The TCP Authentication Option*（TCP-AO）
7. **RFC 6298** — *RTO Calculation*（RTO重传超时）
8. **BBR论文** — *BBR: Congestion-Based Congestion Control*（Google, 2016）
9. **MITRE ATT&CK** — *T1046 (Network Service Scanning)*, *T1572 (Protocol Tunneling)*
10. **CVE-2018-5390** — *SACK Panic Vulnerability*

---

**总结**：TCP是现代网络通信的“毛细血管”，也是几乎所有内网攻击流量（SMB/RDP/HTTP/SSH）的传输底座。其核心在于**序列号机制**、**窗口管理**（流量控制+拥塞控制）和**连接状态机**。SYN Flood、RST攻击、会话劫持、端口扫描、窗口缩放隐蔽信道、SACK Panic构成TCP的六大攻击面；SYN Cookie、TCP-AO、ISN随机化、uRPF/DAI构成防御纵深。掌握本文内容后，建议读者将TCP与ARP、IP、ICMP、路由协议串联，构建完整的网络层-传输层攻防知识体系。下一步，应用层协议（HTTP/SMB/Kerberos）将是你的学习高地——理解TCP的字节流，就理解了这些应用层攻击的“传输底座”。

---

*本文修订于2026年8月，基于Ubuntu 22.04 LTS（内核5.15）/ Kali Linux 2025.1 / Windows 11 22H2 / Wireshark 4.2.6 / Nginx 1.18.0环境验证。TCP行为因操作系统及内核版本存在差异，生产环境中请以具体设备文档为准。*
