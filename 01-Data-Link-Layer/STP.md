# STP协议深度解析：从BPDU基因序列到二层攻防实战

> **实验环境**：Cisco Catalyst 3850（IOS XE 16.12）/ Cisco 2960（IOS 15.0(2)）/ Kali Linux 2025.1（yersinia 0.7.3、scapy 2.5.0）
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。

## 一、协议解剖：BPDU报文的“基因序列”

STP（Spanning Tree Protocol，IEEE 802.1D-2004）的所有秘密都写在BPDU（Bridge Protocol Data Unit）里。BPDU**不封装在IP包中**，而是**直接封装在IEEE 802.3以太网帧中**，目的MAC地址是著名的受限制组播地址：`01:80:C2:00:00:00`（该地址范围被IEEE 802.1D定义为“不跨网桥转发”的控制面地址）。

### 完整的BPDU帧结构（IEEE 802.1D-2004标准）

```
┌─────────────────────────────────────────────────────────────┐
│ 以太网首部（14字节）                                        │
│  目的MAC: 01:80:C2:00:00:00（STP组播，不跨交换机转发）      │
│  源MAC:交换机发送端口的MAC地址                              │
│  长度:0x0026（=38字节，LLC 3B + BPDU 35B） ← 注意非EtherType│
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
> **关键注意**：STP BPDU使用**IEEE 802.2 LLC封装**。以太网头部长度字段为38（0x0026）。不足以太网最小帧长64字节的部分，由物理层在尾部自动填充0。

## 二、选举算法的“原子级”拆解

### 2.1 根桥选举：四步走
初始时，每个交换机都认为自己是根桥。交换机收到BPDU后，提取“根桥ID”与本机保存的比较：**先比优先级（数值越小越优），再比MAC地址（数值越小越优）**。若收到的更优，则更新并中继该BPDU。

### 2.2 端口角色选举：决定性因子
端口角色选举遵循**严格优先序**：
1. **最低根桥ID**
2. **最低根路径开销**（根桥相同，比从端口到达根桥的累积开销）
3. **最低发送者桥ID**（开销相同，比对端交换机的桥ID）
4. **最低发送者端口ID**（对端交换机也相同，比对端发送BPDU的端口ID）

### 2.3 路径开销标准
Cisco默认采用短格式（16位），华为/H3C默认采用长格式（32位）。100Mbps在Cisco中开销为19，在长格式中为200,000。混合组网时需统一：`spanning-tree pathcost method long`。

## 三、精确的收敛时间计算（数学建模）

传统STP的收敛时间是它最大的性能短板。必须区分两种故障场景：

### 3.1 直接故障（物理链路断开或设备断电）
直连根桥的交换机端口立刻检测到物理载波丢失，无需等待Max Age，直接进入Listening状态。
`收敛时间 = 2 × Forward Delay = 15 + 15 = 30秒`

### 3.2 间接故障（链路未断但对端静默死机）
交换机需等待**Max Age（默认20秒）** 未收到BPDU才判定故障。
`总收敛时间 = Max Age + 2 × Forward Delay = 20 + 15 + 15 = 50秒`

这30-50秒的延迟正是RSTP（802.1w）问世的直接驱动力。

## 四、攻防实战的“手术刀级”细节

> ⚠️ **风险提示**：`yersinia` 等工具会对二层拓扑造成毁灭性打击，严禁在非隔离实验环境运行。

### 4.1 攻击工具工作原理（以 `yersinia` 为例）
运行Root抢占攻击时，`yersinia` 构造以太网帧（目的MAC `01:80:C2:00:00:00`），将BPDU载荷中的“根桥ID”优先级设为 `0`，以极高频率发送。由于 `0` 小于合法交换机默认的32768，全网被迫将攻击机视为新根桥，所有根端口指向攻击者，实现MITM。

### 4.2 攻击变形：TCN泛洪攻击
攻击者伪造TCN BPDU（类型0x80）持续发送。在传统STP中，根桥收到后会泛洪带TC标志的配置BPDU，全网交换机将MAC老化时间缩短至15秒，导致MAC表频繁刷新，单播泛洪，网络性能崩溃。
**对RSTP的无效性**：RSTP废弃了TCN BPDU，感知变更时直接发带TC标志的RSTP BPDU并刷新MAC表。但需注意，攻击者仍可通过泛洪RSTP BPDU造成控制面DoS。

### 4.3 防御的底层逻辑

#### 4.3.1 BPDU Guard（硬件级切断）
交换机ASIC对STP组播MAC设有硬件过滤规则，上送CPU。BPDU Guard启用时，CPU收到该帧立即将端口置为 `errdisable`。
配置：`spanning-tree portfast bpduguard default`（全局生效）。

#### 4.3.2 Root Guard（根桥位置锁定）
在端口启用 `spanning-tree guard root` 后，如果收到比当前根桥**更优**的BPDU，端口进入 **Root-Inconsistent** 状态，阻塞数据但继续监控BPDU。这彻底阻断了下游设备抢占根桥的可能。一旦攻击停止，端口可自动恢复。

#### 4.3.3 Root Guard + BPDU Guard 组合矩阵
| 端口场景 | 推荐配置 | 防御目标 |
|:---|:---|:---|
| **接入端口（连终端）** | PortFast + BPDU Guard | 阻止非法交换机/攻击机接入 |
| **级联端口（连下游交换机）** | Root Guard | 阻止下游抢占根桥 |

## 五、RSTP（802.1w）与MSTP（802.1s）的深度差异

### 5.1 RSTP的“核武器”级改进

#### 5.1.1 提议/同意机制
1. 上游指定端口发送 `Proposal=1` 的RSTP BPDU。
2. 下游收到后，阻塞本设备所有其他非边缘端口，回复 `Agreement=1`。
3. 上游收到后立刻进入Forwarding。
在全双工链路上，该过程<1秒完成。

#### 5.1.2 RSTP端口角色扩展
| 端口角色 | 定义 | 状态 |
|:---|:---|:---|
| **根端口** | 本机到达根桥的最优路径端口 | Forwarding |
| **指定端口** | 每个网段上到达根桥的最佳端口 | Forwarding |
| **替代端口** | 本交换机上根端口的备用端口（连接对端交换机） | Discarding |
| **备份端口** | 本交换机上指定端口的备份（仅存于共享介质） | Discarding |

> **语义关键**：Alternate和Backup都是本交换机上的端口阻塞角色。Alternate是另一条连向根桥的备份链路；Backup是同一共享网段上的冗余端口。

### 5.2 MSTP（802.1s）的工程价值
RSTP虽快，但所有VLAN共享一棵树，无法做负载均衡。MSTP允许将VLAN映射到不同STP实例，实现 Instance 1 走左侧链路，Instance 2 走右侧链路。
```cisco
spanning-tree mode mst
spanning-tree mst configuration
 name REGION1
 instance 1 vlan 10,20,30
 instance 2 vlan 40,50,60
!
spanning-tree mst 1 priority 4096   ! 实例1根桥
spanning-tree mst 2 priority 8192   ! 实例2备份
```

## 六、终极配置模板（Cisco生产环境标准）

### 6.1 接入层交换机
```cisco
spanning-tree mode rapid-pvst
spanning-tree portfast default
spanning-tree portfast bpduguard default
!
interface GigabitEthernet0/1
 description CONNECT_TO_USER_PC
 switchport mode access
 switchport access vlan 10
 ! 全局已配置，接口下无需重复
```

### 6.2 汇聚/核心交换机（级联端口）
```cisco
interface GigabitEthernet0/24
 description UPLINK_TO_ACCESS
 switchport mode trunk
 spanning-tree guard root            ! 防止下游抢占根桥
 ! RSTP在全双工链路默认即为point-to-point，无需强制配置
```

### 6.3 STP安全基线检查清单
| 检查项 | 基线标准 |
|:---|:---|
| 根桥位置 | 固定为核心交换机，优先级≤4096 |
| BPDU Guard | 所有Access端口启用 |
| Root Guard | 所有连接下游交换机的端口启用 |
| STP模式 | 至少RSTP（rapid-pvst或mst） |

## 七、总结

STP协议是二层网络的“拓扑守护者”，其BPDU中的每一个字段都是攻防双方争夺的制高点。攻击者通过伪造BPDU抢占根桥或泛洪TCN来扰乱网络，防御方通过Root Guard锁定根桥位置、通过BPDU Guard切断非法接入。理解STP从“慢速收敛”到RSTP“提议/同意”的演进，以及在MSTP中实现VLAN级负载均衡，是构建高可用大二层网络的必修课。下一步，建议将STP知识与VLAN安全、MAC地址表攻防串联，构建完整的二层安全知识体系。

## 参考文献与延伸阅读

1. **IEEE 802.1D-2004** — *MAC Bridges*（STP标准规范）
2. **IEEE 802.1w-2001** — *Rapid Reconfiguration of Spanning Tree*（RSTP）
3. **IEEE 802.1s-2002** — *Multiple Spanning Trees*（MSTP）
4. **Cisco STP Configuration Guide**（Catalyst 3850/9300官方文档）
5. **MITRE ATT&CK** — *T1557: Adversary-in-the-Middle*

---

*本文修订于2026年8月，基于Cisco IOS 15.0(2)/XE 16.12环境验证。*
