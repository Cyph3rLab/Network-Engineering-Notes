# MAC地址表（CAM表）深度解析：从二层转发原理到现代二层攻防实战

> **实验环境**：Cisco Catalyst 3850（IOS XE 16.12）/ Cisco 2960（IOS 15.0(2)）/ Ubuntu 22.04（bridge-utils）/ Kali Linux 2025.1（macof、macchanger）
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。

## 一、MAC地址表基础

MAC地址表（也称CAM表）是二层交换机实现精确转发的核心数据结构。其本质是一张维护“**MAC地址 ↔ 交换机物理端口 ↔ VLAN**”映射关系的动态数据库，存储在交换机的专用ASIC硬件芯片中。

交换机在接收到数据帧时，剥离前导码和帧起始定界符（SFD）后，解析以太网帧头，提取**目的MAC地址**查询本表，从而决定数据帧的出向端口。

> 规范依据：IEEE 802.1D-2004（MAC Bridges）第7.7节“Filtering Database”。

## 二、MAC地址学习机制

### 2.1 源MAC学习原则
交换机刚启动时，MAC地址表为空。交换机通过持续监听进入端口的数据帧来**动态学习**表项。
**核心学习原则**（IEEE 802.1D 7.7.2）：交换机**永远提取数据帧的“源MAC地址”进行学习**，与“目的MAC地址”无关。

若交换机在端口Gi1/0/1收到源MAC为 `00:0c:29:a1:b2:c3` 的帧：
1. 若表项不存在，创建新表项并启动老化计时器（默认300秒）。
2. 若表项已存在但端口不同，则更新端口，并记录 **MAC漂移** 事件（需配置 `mac address-table notification mac-move`）。

### 2.2 MAC地址老化机制
系统为每个动态表项分配老化定时器（Cisco默认300秒，部分华为默认150秒）。若在该周期内未从对应端口收到以该MAC为源地址的帧，表项将被删除。

### 2.3 MAC地址表容量与硬件约束
企业级交换机的CAM表容量存在物理上限（存储在ASIC TCAM中）。当MAC地址表条目数达到硬件上限时，交换机无法再学习新的MAC地址，新出现的源MAC所对应的帧将被视为未知单播并进行泛洪。

## 三、转发与泛洪机制

交换机完成源MAC学习后，将根据数据帧的“目的MAC地址”执行以下三种转发逻辑之一：

### 3.1 已知单播转发
若目的MAC地址在表中存在映射，且映射端口与接收端口**不同**，交换机直接从该出向端口转发。若映射端口与接收端口**相同**，交换机**丢弃**该帧。

### 3.2 未知单播泛洪
若目的MAC地址在表中**查不到**，交换机将执行**泛洪**：向除接收端口外的所有同VLAN端口复制转发该数据帧。这造成了带宽浪费和潜在的隐私暴露风险。

### 3.3 广播与组播泛洪
- **广播帧（目的MAC = `FF:FF:FF:FF:FF:FF`）**：强制泛洪。
- **组播帧**：未启用IGMP Snooping时按泛洪处理；启用后仅转发至组播组成员端口。

> **关键区分**：广播泛洪是协议强制行为，未知单播泛洪是CAM表项缺失导致的保底行为。

## 四、ARP与MAC地址表的协同逻辑

以主机A首次访问同网段主机B为例：
1. **ARP请求触发**：主机A构造ARP Request（目的MAC=广播，源MAC=AA:AA）。
2. **交换机处理请求**：学习源MAC `AA:AA → Gi1/0/1`；因目的MAC是广播，执行泛洪。
3. **ARP响应回复**：主机B回复ARP Reply（目的MAC=AA:AA单播，源MAC=BB:BB）。
4. **交换机处理响应**：学习源MAC `BB:BB → Gi1/0/2`；查表命中 `AA:AA`，执行精准单播转发。

## 五、攻防视角分析（演进版）

### 5.1 历史攻击手法：MAC Flooding（在2026年企业网已基本失效）

**攻击原理**：攻击者使用 `macof` 在极短时间内发送大量伪造源MAC的帧，企图填满CAM表。
**CAM表满后的真实行为（纠正常见误区）**：
- **低端交换机**：所有流量退化为泛洪（近似Hub）。
- **企业级中高端**：已有MAC条目仍精准转发，但新MAC地址的流量被泛洪，学习引擎停止。
**结论**：安全评估中**不应假设表满后仍有任何精准转发的保证**。

**为何该技术已基本失效**：
端口安全在接入层已广泛部署。攻击者若运行 `macof`，端口在达到最大MAC数量后会立即触发违例（`shutdown`），导致攻击者自身断网。
**例外场景**：在OT工控网络、老旧未加固网络中仍然有效。

**防御配置**：
```cisco
interface GigabitEthernet1/0/1
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation shutdown
 switchport port-security mac-address sticky
```

### 5.2 现代高危攻击手法

#### 手法A：MAC地址欺骗——通过时间窗竞争绕过端口安全

- **攻击原理**：端口安全仅限制端口学习MAC的**数量**，不校验全局唯一性。攻击者将MAC改为合法终端MAC，由于合法终端仍在发包，交换机表项会在合法端口与攻击者端口间不断更新，形成**MAC漂移**。攻击者需以高于合法终端的发包频率持续发送伪造帧，在时间窗竞争中胜出。
- **防御**：
  - 启用MAC漂移检测与自动处置（`mac address-table notification mac-move`）。
  - **部署 IPSG（IP Source Guard）**：结合DHCP Snooping绑定表，在硬件ASIC层检查入站帧的源IP和源MAC，不匹配则直接丢弃，彻底阻断时间窗竞争。
  - 部署802.1X+端口安全Sticky MAC实现“用户+MAC”动态绑定。

> ⚠️ **风险提示**：以下命令会导致网络产生大量广播包并引发交换机CPU升高，严禁在非隔离实验环境执行。
```bash
# 修改为伪造MAC并持续发送ARP通告以维持表项
sudo ip link set eth0 down
sudo ip link set eth0 address 00:50:56:xx:xx:xx
sudo ip link set eth0 up
while true; do sudo arping -c 1 -A -I eth0 192.168.1.10; sleep 0.05; done
```

#### 手法B：VLAN双标签跳跃——突破VLAN隔离

- **攻击原理**（必须跨两台交换机）：
  1. 攻击者接入交换机A的Access口（属于Native VLAN 1），发送带有双层Tag的帧（外层VLAN 1，内层VLAN 30）。
  2. 交换机A的Access口收到帧，剥离外层Tag，将帧视为VLAN 1的流量 internally 转发至Trunk口。
  3. 交换机A的Trunk口发出该帧时，因VLAN 1是Native VLAN，默认不再封装Tag，导致带有内层VLAN 30 Tag的帧被直接发送到链路上。
  4. 交换机B的Trunk口收到该帧，将残留的内层Tag误认为合法的802.1Q Tag，从而在VLAN 30内泛洪。
- **关键限制**：该攻击是**单向的**，仅适用于单向数据注入。
- **防御**：
  - 更改Native VLAN为未使用VLAN：`switchport trunk native vlan 999`
  - 显式修剪未使用的VLAN：`switchport trunk allowed vlan 10,20,30`
  - 强制Trunk对Native VLAN打Tag（Cisco：`vlan dot1q tag native`）

#### 手法C：STP操纵——控制面拓扑劫持

- **攻击原理**：攻击者发送伪造的更优BPDU包，试图成为根桥，改变二层拓扑实现MITM。
- **防御（组合部署，注意场景区分）**：
  - **BPDU Guard**（`spanning-tree bpduguard enable`）：部署在**纯终端接入端口**，收到任何BPDU即触发Err-Disable。防御的是非法交换机接入。
  - **Root Guard**（`spanning-tree guard root`）：部署在**交换机间级联端口**（如汇聚连接接入的端口），收到更优BPDU时进入Root-Inconsistent状态。防御的是下游设备抢占根桥。**注意：不应与BPDU Guard配置在同一端口。**
  - 推荐接入侧基线：**PortFast + BPDU Guard**。

### 5.3 企业级防御纵深矩阵（2026年实战标准）

| 防御层级 | 技术手段 | 对抗的攻击 |
| :--- | :--- | :--- |
| **接入层（终端）** | 端口安全（Port Security） | MAC Flooding |
| **接入层增强** | IPSG (IP Source Guard) + DHCP Snooping | MAC克隆/IP欺骗 |
| **身份认证** | 802.1X + Sticky MAC联动 | 非法终端接入 |
| **Trunk接口** | Native VLAN改号 + VLAN Pruning + Tag Native | VLAN双标签跳跃 |
| **控制面防护** | BPDU Guard (接入) + Root Guard (级联) | STP操纵 |
| **监控层** | MAC漂移检测 + NDR异常分析 | MAC欺骗的早期发现 |

## 六、运维排查与避坑指南

### 6.1 常用排查命令
| 场景 | Cisco IOS命令 |
| :--- | :--- |
| 查看指定端口MAC | `show mac address-table interface Gi1/0/1` |
| 查看MAC表容量 | `show mac address-table count` |
| 查看MAC漂移记录 | `show mac address-table flapping` (需IOS 15.0(1)SE+) |

### 6.2 异常特征识别与诊断
| 异常现象 | 可能根因 | 处置 |
| :--- | :--- | :--- |
| **单端口学习到海量MAC** | MAC Flooding攻击 或 下游存在非法NAT | 启用端口安全，限制MAC数量 |
| **同一MAC在两端口间快速切换** | 物理环路 或 MAC克隆攻击 | 观察日志时间戳：环路通常规律且秒级，攻击间隔极短。环路修复STP，攻击启用漂移检测 |
| **未知单播泛洪加剧** | CAM表接近/已满 | 检查剩余容量，升级硬件或启用风暴控制 |

### 6.3 常见认知误区
- **交换机根据目的MAC学习**：错，仅根据进入端口的数据帧的“源MAC”学习。
- **CAM表溢出后交换机变集线器**：中高端交换机仍对已有表项精准转发，安全评估应按最坏情况规划。
- **端口安全能彻底防御MAC欺骗**：端口安全限制的是数量，不校验唯一性。必须配合IPSG或802.1X。

## 七、二层安全基线检查清单

| 检查项 | 基线标准 |
| :--- | :--- |
| 端口安全（接入端口） | `maximum 2` + `violation shutdown` + `sticky` |
| MAC漂移检测 | `mac address-table notification mac-move` 启用 |
| BPDU Guard（接入端口） | `spanning-tree bpduguard enable` |
| Root Guard（级联端口） | `spanning-tree guard root` |
| Native VLAN（Trunk口） | 非VLAN 1且显式Tagged |
| Storm Control | 广播/未知单播限制 ≤ 10% |

## 八、总结

MAC地址表是二层交换的基石，也是内网安全的第一道防线。理解攻击从“MAC Flooding（数量填满）”到“MAC Spoofing（内容伪造）”再到“VLAN跳跃（边界突破）”的演进路线，是构建纵深防御体系的必修课。掌握本节内容，读者应具备独立分析MAC地址表结构与转发逻辑的能力，并在企业交换机上熟练部署端口安全、IPSG、BPDU Guard等安全基线。下一步，建议将MAC表知识与ARP协议、VLAN安全串联，构建完整的二层攻防知识底座。

## 参考文献与延伸阅读

1. **IEEE 802.1D-2004** — *MAC Bridges*
2. **IEEE 802.1Q-2014** — *VLAN Bridge Standard*
3. **RFC 826** — *Ethernet Address Resolution Protocol*
4. **MITRE ATT&CK** — *T1557: Adversary-in-the-Middle*
5. **Cisco Catalyst Layer 2 Switching Configuration Guide**

---

*本文修订于2026年8月，基于Cisco IOS 15.0(2)/XE 16.12环境验证。交换机行为因厂商及芯片型号存在差异，生产环境中请以具体设备文档为准。*
