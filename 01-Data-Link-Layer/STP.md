# STP协议深度解析：从BPDU基因序列到二层攻防实战

> **实验环境**：Cisco Catalyst 3850（IOS XE 16.12.01）/ Cisco Catalyst 2960（IOS 15.0(2)SE）/ Kali Linux 2025.1（yersinia 0.7.3-1、scapy 2.5.0）
>
> **合规声明**：本文所有攻击技术描述**仅限用于网络安全防护研究与获得书面授权的隔离环境安全测试**。未经授权的STP操纵、BPDU注入、TCN泛洪等行为，违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条，切勿用于非法目的。


## 一、协议解剖：BPDU报文的"基因序列"

STP（Spanning Tree Protocol，IEEE 802.1D-2004）的所有逻辑都封装在BPDU（Bridge Protocol Data Unit）中。BPDU**不封装在IP包中**，而是**直接封装在IEEE 802.3以太网帧中**，目的MAC地址为受限制组播地址：`01:80:C2:00:00:00`。

> **工程安全意义**：该组播地址在IEEE 802.1D中被定义为"不跨网桥转发"（Non-Forwardable）。这意味着BPDU在交换机上被接收并送CPU处理后，**不会转发到其他端口**。正是这一机制使得BPDU Guard能在接入端口有效生效——BPDU不会跨交换机传播到更上层网络。

### 完整的BPDU帧结构（IEEE 802.1D-2004标准）

```
┌─────────────────────────────────────────────────────────────┐
│ 以太网首部（14字节）                                        │
│  目的MAC: 01:80:C2:00:00:00（STP组播）                      │
│  源MAC: 交换机发送端口的MAC地址                             │
│  长度: 0x0026（=38字节，LLC 3B + BPDU 35B）                 │
├─────────────────────────────────────────────────────────────┤
│ LLC头部（3字节）— IEEE 802.2                                │
│  DSAP: 0x42（Destination SAP，STP）                         │
│  SSAP: 0x42（Source SAP，STP）                              │
│  Ctrl: 0x03（无编号帧，UI）                                 │
├─────────────────────────────────────────────────────────────┤
│ BPDU载荷（35字节固定部分）                                  │
│  协议ID: 0x0000（固定，表示STP）                            │
│  版本:   0x00（STP）或 0x02（RSTP）或 0x03（MSTP）          │
│  BPDU类型: 0x00（配置BPDU）或 0x80（TCN，仅STP）            │
│  标志位:  1字节（RSTP/MSTP中用于Proposal/Agreement/TC）     │
│  根桥ID:  8字节（2字节优先级 + 6字节MAC地址）               │
│  根路径开销: 4字节（长格式32位；短格式时仅低16位有效）      │
│  发送者桥ID: 8字节                                          │
│  发送者端口ID: 2字节（1字节优先级 + 1字节端口号）           │
│  消息寿命: 2字节（根桥发送时为0，每跳+1）                   │
│  最大寿命: 2字节（默认20秒）                                │
│  Hello时间: 2字节（默认2秒，根桥发送周期）                  │
│  转发延迟: 2字节（默认15秒）                                │
└─────────────────────────────────────────────────────────────┘
```

> **关键注意**：STP BPDU使用**IEEE 802.2 LLC封装**，以太网帧长度字段值为38（0x0026），不包含以太网尾部填充。不足最小帧长64字节的部分由物理层自动填充。


## 二、选举算法的"原子级"拆解

### 2.1 根桥选举：四步决策链

初始时，每个交换机都认为自己是根桥。交换机收到BPDU后，提取"根桥ID"与本机保存的比较：**先比优先级（数值越小越优），再比MAC地址（数值越小越优）** 。若收到的更优，则更新并中继该BPDU。

### 2.2 端口角色选举：决定性因子优先序

端口角色选举遵循**严格优先序**（依次比较，一旦分出胜负即停止）：
1. **最低根桥ID**
2. **最低根路径开销**（根桥相同，比从端口到达根桥的累积开销）
3. **最低发送者桥ID**（开销相同，比对端交换机的桥ID）
4. **最低发送者端口ID**（对端交换机也相同，比对端发送BPDU的端口ID）

### 2.3 路径开销标准（厂商与模式差异）

路径开销值因厂商、STP模式和标准版本而异，混合组网时必须统一格式：

| 厂商/平台 | 默认格式 | 值域 | 100Mbps开销 |
|:---|:---|:---:|:---:|
| Cisco Catalyst（PVST+模式） | 短格式（16位） | 0～65,535 | 19 |
| Cisco Catalyst（RSTP/MSTP模式，IOS 15.x+） | **长格式（32位）** | 1～200,000,000 | 200,000 |
| 华为/H3C（默认） | 长格式 | 1～200,000,000 | 200,000 |
| IEEE 802.1D-2004标准 | — | — | 200,000（长格式）/ 19（短格式） |

**Cisco统一命令**：
```cisco
spanning-tree pathcost method long   ! 全网切换至长格式
```

> **历史注意**：IEEE 802.1D-1998中100Mbps开销为10，2004修订版改为19，若混合新旧设备需确认一致。


## 三、收敛时间计算（传统STP vs RSTP对比）

### 3.1 传统STP（IEEE 802.1D）收敛时间

以下计算**仅适用于传统STP（802.1D）** ，RSTP的收敛时间请参见第4.1节。

| 故障类型 | 判定机制 | 收敛时间 | 公式 |
|:---|:---|:---:|:---|
| **直接故障**（物理链路断开） | 端口立即检测载波丢失 | **30秒** | `2 × Forward_Delay = 30秒` |
| **间接故障**（对端静默死机） | 等待Max Age（20秒） | **50秒** | `Max_Age + 2 × Forward_Delay = 50秒` |

### 3.2 RSTP（IEEE 802.1w）快速收敛

RSTP通过**Proposal/Agreement握手**实现在全双工点对点链路上的亚秒级收敛（<1秒），彻底解决了传统STP 30-50秒的性能瓶颈（详见第4.1节）。


## 四、RSTP（802.1w）与MSTP（802.1s）的深度差异

### 4.1 RSTP的Proposal/Agreement机制

**触发前提（缺一不可）** ：
1. 链路两端协商为**点对点（Point-to-Point）** ——Cisco中全双工链路默认视为P2P（半双工禁用Proposal/Agreement，回退至传统STP收敛）；
2. 发送Proposal的端口必须是**指定端口（Designated Port）** ；
3. 下游交换机在收到Proposal后需完成与下游设备的同步，再回复Agreement。

**工作流程**：
1. 上游指定端口发送 `Proposal=1` 的RSTP BPDU；
2. 下游收到后，阻塞本设备所有其他非边缘端口，回复 `Agreement=1`；
3. 上游收到后立刻进入Forwarding。

满足以上条件时，全双工链路上收敛时间 **<1秒**。

### 4.2 RSTP端口角色扩展

| 端口角色 | 定义 | 状态 |
|:---|:---|:---|
| **根端口** | 本机到达根桥的最优路径端口 | Forwarding |
| **指定端口** | 每个网段上到达根桥的最佳端口（通常为上游端口） | Forwarding |
| **替代端口** | 本交换机上**根端口的备用**（连接另一条到根桥的路径） | Discarding |
| **备份端口** | 本交换机上**指定端口的备用**（仅存于共享介质场景，如同一Hub上的两条链路） | Discarding |

> **语义关键**：Alternate和Backup都是阻塞角色，区别在于Alternate提供的是另一条**上行路径**（到根桥的备选），Backup提供的是同一网段上的**下行冗余**。

### 4.3 MSTP（802.1s）的工程价值

RSTP虽快，但所有VLAN共享一棵树，无法负载均衡。MSTP允许将VLAN映射到不同STP实例，实现Instance 1走左侧链路、Instance 2走右侧链路。

**完整配置示例（Cisco，含revision）** ：
```cisco
spanning-tree mode mst
spanning-tree mst configuration
 name REGION1
 revision 1                     ! 【必须】区域内所有交换机一致
 instance 1 vlan 10,20,30
 instance 2 vlan 40,50,60
!
spanning-tree mst 1 priority 4096   ! 实例1根桥（优先级必须是4096的倍数）
spanning-tree mst 2 priority 8192   ! 实例2备份根桥
```


## 五、攻防实战的"手术刀级"细节

> **⚠️ 严重风险警示**：`yersinia` 等工具会对二层拓扑造成毁灭性打击，**严禁在非隔离实验环境运行**。`yersinia`需从官方源安装（Kali中`apt install yersinia`），依赖`libnet`等库，安装前需确认网络可达。

### 5.1 攻击工具工作原理（以 `yersinia` 为例）

运行Root抢占攻击时，`yersinia`构造以太网帧（目的MAC `01:80:C2:00:00:00`），将BPDU载荷中的"根桥ID"优先级设为`0`，以极高频率发送。由于`0`小于合法交换机默认的32768，全网被迫将攻击机视为新根桥，所有根端口指向攻击者，实现流量路径重定向（**真正的MITM需结合ARP欺骗完成数据拦截**）。

### 5.2 攻击变形：TCN泛洪攻击

**传统STP域内**：攻击者伪造TCN BPDU（类型0x80）持续发送。根桥收到后泛洪带TC标志的配置BPDU，全网交换机将MAC老化时间缩短至15秒，导致MAC表频繁刷新、单播泛洪加剧、网络性能崩溃。

**纯RSTP域内**：RSTP废弃了TCN BPDU（类型0x80）——感知拓扑变更时直接通过RSTP BPDU标志位传播TC事件。攻击者在**纯RSTP域内**伪造TCN BPDU无效。

**⚠️ 混合环境边界情况**：在RSTP与旧STP域交界处，边界交换机在兼容模式下**仍会接收并转换旧域的TCN**为本域的RSTP TC事件。若网络中存在STP/RSTP混合模式，TCN泛洪攻击仍可通过边界间接影响RSTP域。安全评估中**应优先确认全网STP模式是否统一**。

### 5.3 防御的底层逻辑

#### 5.3.1 BPDU Guard（硬件级切断）
交换机ASIC对STP组播MAC设硬件过滤规则，上送CPU。BPDU Guard启用时，CPU收到BPDU立即将端口置为`errdisable`。
```cisco
spanning-tree portfast bpduguard default   ! 全局生效（所有Access端口）
```

#### 5.3.2 Root Guard（根桥位置锁定）
在端口启用`spanning-tree guard root`后，若收到比当前根桥**更优**的BPDU，端口进入**Root-Inconsistent**状态（阻塞数据但继续监控BPDU）。一旦攻击停止，端口可自动恢复（需`errdisable recovery`启用）。

#### 5.3.3 Loop Guard（单向链路防护）
为防止因单向链路故障导致的"替代端口错误进入Forwarding"造成的环路，在级联端口启用：
```cisco
spanning-tree guard loop
```

#### 5.3.4 BPDU Guard + Root Guard + Loop Guard 配置矩阵（Cisco环境）

| 端口场景 | 推荐配置 | 防御目标 |
|:---|:---|:---|
| **接入端口（连终端/服务器）** | PortFast + BPDU Guard | 阻止非法交换机/攻击机接入 |
| **级联端口（连下游交换机）** | Root Guard + Loop Guard | 阻止下游抢占根桥 + 防单向环路 |
| **级联端口（连接不可信网络）** | BPDU Filter（抑制收发） | 防止BPDU攻击影响本域 |


## 六、生产环境STP选型与配置模板

### 6.1 STP选型决策树

| 网络规模/需求 | 推荐STP模式 | 理由 |
|:---|:---|:---|
| 小型网络（<10台交换机，无负载均衡需求） | **rapid-pvst** | 快速收敛 + 单实例简单 |
| 中大型网络（多VLAN，需要流量分流） | **MST** | 多实例负载均衡 + 硬件资源节省 |
| 数据中心（超低延迟、大规模VLAN） | **MST + PortFast默认启用** | 快速收敛 + VXLAN/EVPN兼容 |
| Cisco与第三方厂商混合 | **MST**（非Cisco私有协议） | 跨厂商兼容性最佳 |

### 6.2 接入层交换机配置模板
```cisco
spanning-tree mode rapid-pvst
spanning-tree portfast default
spanning-tree portfast bpduguard default
!
interface GigabitEthernet0/1
 description CONNECT_TO_USER_PC
 switchport mode access
 switchport access vlan 10
 ! 全局已配置，接口下无需重复（若需接口级别覆盖）
```

### 6.3 汇聚/核心交换机（级联端口）
```cisco
interface GigabitEthernet0/24
 description UPLINK_TO_ACCESS
 switchport mode trunk
 spanning-tree guard root            ! 防止下游抢占根桥
 spanning-tree guard loop            ! 防单向链路环路
 ! RSTP在全双工链路默认即为P2P，无需强制配置
```

### 6.4 STP安全基线检查清单

| 检查项 | 基线标准 | 配置命令 |
|:---|:---|:---|
| 根桥位置 | 固定为核心交换机，优先级≤4096 | `spanning-tree vlan 1 root primary` |
| BPDU Guard | 所有Access端口启用 | `spanning-tree portfast bpduguard default` |
| Root Guard | 所有连接下游交换机的级联端口启用 | `spanning-tree guard root` |
| Loop Guard | 级联端口和根端口启用 | `spanning-tree guard loop` |
| STP模式 | 至少RSTP（rapid-pvst或mst） | 按选型决策树选择 |


## 七、总结

STP协议是二层网络的"拓扑守护者"，其BPDU中的每一个字段都是攻防双方争夺的制高点。攻击者通过伪造BPDU抢占根桥、泛洪TCN扰乱MAC表或强制版本降级来破坏网络；防御方通过Root Guard锁定根桥位置、通过BPDU Guard切断非法接入、通过Loop Guard防范单向链路环路。

理解STP从"慢速收敛（30-50秒）"到RSTP"亚秒级Proposal/Agreement"的演进，以及在MSTP中实现VLAN级负载均衡，是构建高可用大二层网络的必修课。下一步，建议将STP知识与VLAN安全、MAC地址表攻防串联，构建完整的二层安全知识体系。


## 参考文献与延伸阅读

### 标准与RFC
- IEEE 802.1D-2004 — *MAC Bridges*（STP标准规范，现为802.1Q-2022的一部分）
- IEEE 802.1w-2001 — *Rapid Reconfiguration of Spanning Tree*（RSTP，已合并入802.1D-2004）
- IEEE 802.1s-2002 — *Multiple Spanning Trees*（MSTP，已合并入802.1Q-2022）

### 工程文档
- Cisco Catalyst 3850 Layer 2 Switching Configuration Guide, IOS XE Release 16.x
- Cisco "Spanning Tree Protocol (STP) PortFast, BPDU Guard, BPDU Filter, Root Guard, and Loop Guard" — 官方配置指南
- MITRE ATT&CK — [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)

---

*本文修订于2026年8月，基于Cisco IOS 15.0(2)SE / IOS XE 16.12.01环境验证。不同厂商STP行为存在差异，生产环境请以具体设备官方文档为准。*
