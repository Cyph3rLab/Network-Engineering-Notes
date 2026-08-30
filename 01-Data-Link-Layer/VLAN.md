# VLAN虚拟局域网深度解析：从802.1Q原理到二层隔离与攻击防御实战

> **实验环境**：Cisco Catalyst 3850（IOS XE 16.12.01）/ Cisco Catalyst 2960（IOS 15.0(2)SE）/ VMware vSphere 8.0 / Kubernetes 1.28（Calico CNI）/ Kali Linux 2025.1（yersinia 0.7.3-1、scapy 2.5.0）
>
> **合规声明**：本文所有攻击技术描述**仅限用于网络安全防护研究与获得书面授权的隔离环境安全测试**。未经授权的VLAN跳跃、DTP滥用、Double Tagging注入等行为，违反《中华人民共和国网络安全法》第二十七条及《中华人民共和国刑法》第二百八十五条，切勿用于非法目的。


## 一、VLAN的基本概念

VLAN（Virtual Local Area Network，虚拟局域网）是一种在物理交换机上划分多个逻辑独立网络的技术。在没有VLAN的环境中，所有设备同属一个广播域；引入VLAN后，虽然设备物理上连接在同一台交换机，逻辑上却相当于处于不同的交换机之中，广播流量被有效隔离。

> **规范来源**：IEEE 802.1Q-2022 “Bridges and Bridged Networks”。


## 二、VLAN的核心应用价值

| 价值维度 | 说明 |
|:---|:---|
| **隔离广播域** | 大规模网络通过VLAN划分，各域广播互不干扰，避免广播风暴消耗带宽和CPU。 |
| **提升网络安全** | 不同VLAN默认无法二层通信。但需注意：**VLAN隔离仅作用于二层，若三层交换机开启了`ip routing`，各VLAN的SVI（交换虚接口）之间默认全互通**，必须依赖**ACL或防火墙策略**实现真正的安全边界。 |
| **简化网络管理** | 物理搬迁时无需重新布线，仅需调整端口所属VLAN。 |


## 三、VLAN的协议定位与802.1Q标签结构

VLAN工作在OSI模型的**数据链路层（第二层）** 。802.1Q标准在以太网帧头中插入一个4字节的标签字段，位于源MAC地址和EtherType/长度字段之间。

```
┌──────────┬──────────┬──────────┬──────────┬──────────┬────────────┐
│  Dst MAC │  Src MAC │ 802.1Q   │ EtherType│ Payload  │    FCS     │
│  (6B)    │  (6B)    │  Tag(4B) │  (2B)    │(46-1500B)│  (4B)      │
└──────────┴──────────┴──────────┴──────────┴──────────┴────────────┘
                          │
                          ▼
               ┌──────────┬──────────────────────────────────────┐
               │  TPID    │                TCI                   │
               │  (2B)    │               (2B)                   │
               ├──────────┼──────┬─────────┬───────┬─────────────┤
               │ 0x8100   │ PCP  │   DEI   │  VID  │             │
               │ 固定值   │(3bit)│  (1bit) │(12bit)│             │
               └──────────┴──────┴─────────┴───────┴─────────────┘
```

- **TPID**：固定值为`0x8100`。QinQ（802.1ad）场景中，外层TPID可为`0x88A8`。
- **VID**：12位，数值范围0–4095。**可用配置范围1–4094**（VLAN 0用于优先级Tag，VLAN 4095保留，均不可配置）。
- **保留VLAN说明**：
  - VLAN 1：默认VLAN（IEEE 802.1Q中称“Default VID”，Cisco默认端口均属于VLAN 1）；
  - VLAN 1002–1005：在**部分Cisco平台（如传统CatOS）** 上保留给FDDI/Token Ring，默认状态下不可用于常规以太网VLAN配置。**但在IOS XE平台（如3850/9300）上，可通过先执行`no vlan 1002-1005`删除后重新利用这些VLAN ID**。生产环境中建议查阅目标平台官方文档以确认具体行为。
- **PCP（Priority Code Point）** ：3位，802.1p优先级（0～7），用于QoS分类。

> **MTU影响**：802.1Q标签插入后，帧长度增加4字节，最大帧长从1518字节变为1522字节（含首部），Payload最大仍为1500字节。若网络中设备未启用Jumbo Frame支持，带标签的帧可能因超过标准MTU而被丢弃。**生产环境中建议在Trunk链路上启用Jumbo Frame（Cisco中配置`mtu 1504`或`system mtu`）以确保MTU一致性。**


## 四、交换机端口模式与帧处理流程

### 4.1 Access端口
- **特性**：仅属于一个VLAN；终端发送的帧不携带标签；交换机接收时打上内部标识，转发时剥离标签。
- **接收带标签帧的行为（关键）** ：
  - 若帧中VID = 端口PVID：**剥离标签**，帧在交换机内部作为该VLAN的无标签帧处理；
  - 若帧中VID ≠ 端口PVID：**丢弃该帧**（IEEE 802.1Q-2022 §9.4.1）。

### 4.2 Trunk端口
- **特性**：允许多个VLAN通过；传输时保留802.1Q标签（Native VLAN除外）。
- **Native VLAN机制（双向）** ：
  - **出方向**：Native VLAN的帧发出时**不携带标签**；
  - **入方向**：收到无标签帧时归入Native VLAN。

> ⚠️ 两端Trunk端口的Native VLAN ID必须一致，否则会产生`%CDP-4-NATIVE_VLAN_MISMATCH`告警，可能导致非预期的VLAN穿越或通信中断。


## 五、VLAN 1的“幽灵风险”与Native VLAN安全加固

### 5.1 为什么VLAN 1是高风险VLAN？

1. **默认配置**：所有交换机端口默认属于VLAN 1；Trunk默认允许VLAN 1通过且Native VLAN默认为1；
2. **控制协议依赖**：VTP、DTP等管理协议默认使用VLAN 1作为管理VLAN（CDP协议EtherType 0x2000，在Cisco工程实现中亦在Native VLAN上传输）；
3. **不可删除**：VLAN 1作为默认VLAN，在大多数Cisco平台**不可删除**（`no vlan 1`被拒绝）。攻击者若接入VLAN 1的Access端口，可借助以上特性发起DTP协商或VLAN跳跃攻击。

### 5.2 生产环境标准配置（双重保护）
```cisco
! 前置条件：确保VLAN 999已在交换机上创建且处于active状态
vlan 999

interface GigabitEthernet0/24
 switchport trunk native vlan 999           ! ① 修改Native VLAN为非默认值
 switchport trunk allowed vlan 10,20,30,999 ! ② 限制允许的VLAN列表
 switchport trunk allowed vlan remove 1     ! ③ 显式拒绝VLAN 1（关键）
```

**验证命令**：
```cisco
show interfaces trunk                      ! 确认Trunk状态、Native VLAN和Allowed VLAN列表
show running-config | include dot1q tag native   ! 确认Native VLAN Tagging是否启用
```


## 六、攻击手法深度拆解

> **⚠️ 严重风险警示**：以下攻击手法的实现工具（yersinia、scapy）高频发包可能导致老款交换机CPU满载宕机，**严禁在非隔离实验环境运行**。攻击者需在操作系统层面创建VLAN子接口或使用支持构造802.1Q Tag的工具（如Scapy的`Dot1Q`层），否则普通应用程序无法发送带Tag的帧。

### 6.1 Switch Spoofing（交换机欺骗）——DTP协议滥用

DTP（Dynamic Trunk Protocol）是Cisco私有协议，用于自动协商链路是否成为Trunk。DTP帧不包含设备类型声明，但包含**协商状态值**（Desirable/Auto/Trunk等）。

**DTP协商生效条件**：
- 端口模式必须为`dynamic desirable`（主动发起）或`dynamic auto`（被动响应）；
- DTP帧在VLAN 1上传输，**由于所有端口默认属于VLAN 1，该条件在默认配置下自动满足**；
- 若目标端口被静态配置为`trunk`或`access`模式，则DTP协商不会改变其模式。

| Cisco型号 | 默认DTP模式 |
|:---|:---|
| Catalyst 2960 | `dynamic desirable` |
| Catalyst 3560/3750 | `dynamic auto` |
| Catalyst 3850/9300 | `dynamic auto`（视IOS版本） |
| 华为/华三 | 不支持DTP（需手动配置Trunk/Access） |

**攻击原理**：
攻击者接入配置为`dynamic auto`或`desirable`的Access端口，发送伪造的DTP协商帧（模式设为Desirable），若目标端口支持DTP协商，则链路被动态切换为Trunk模式，攻击者可访问所有VLAN。

**防御配置**：
```cisco
interface GigabitEthernet0/1
 switchport mode access         ! 强制Access，拒绝DTP协商
 switchport nonegotiate         ! 禁止发送DTP帧；对收到的DTP帧不予响应
```

**注意**：`switchport nonegotiate`仅**禁止发送**DTP协商帧，端口仍可接收DTP帧（但不做响应）。生产环境最安全的做法是直接强制`mode access`，此时即使收到DTP帧亦不影响端口状态。

**验证**：`show interfaces trunk`——攻击端口不应出现在Trunk列表中。

### 6.2 Double Tagging（双标签攻击）——正确机制详解

该攻击利用802.1Q Native VLAN在Trunk出站时不带Tag的机制。

**【修正】攻击前提（关键——默认配置即满足）** ：

Double Tagging攻击的成立依赖于一个在**绝大多数Cisco交换机默认配置下天然满足**的条件：
1. 攻击者接入的Access端口的PVID（默认为**VLAN 1**）与第一台交换机连接第二台交换机的Trunk端口的Native VLAN（默认为**VLAN 1**）**相同**；
2. 该Trunk端口未配置`vlan dot1q tag native`；
3. 攻击者操作系统需配置VLAN子接口或使用支持构造802.1Q Tag的工具（如Scapy）。

> **由于Cisco交换机的VLAN 1是默认VLAN，上述条件在未加固网络中几乎总是成立**——攻击者只需物理接入任意Access端口即可发起攻击，无需任何特殊配置前提。这正是VLAN 1被称为“高风险VLAN”的根本原因。

**攻击原理（防御性描述）** ：

1. 攻击者构造并发送一个**带有双层802.1Q标签**的以太网帧：
   - **外层Tag** = Native VLAN ID（如VLAN 1）
   - **内层Tag** = 攻击目标VLAN ID（如VLAN 20）

2. **第一台交换机的Access端口（PVID = VLAN 1）** 收到该帧。根据802.1Q标准，因外层VID（1）等于端口PVID（1），交换机**剥离外层标签**。此时该帧在交换机内部被视为**VLAN 1的无标签帧**，但**内层VLAN 20标签仍作为Payload的一部分残留在帧中**。

3. **关键步骤**：该帧在交换机内部被标记为VLAN 1的帧，并被转发至连接第二台交换机的**Trunk端口**。该Trunk端口的Native VLAN恰好也是VLAN 1。当该帧从Trunk端口发送出去时，因Native VLAN（VLAN 1）默认**不带标签**，交换机**不再添加任何外层标签**，直接将带有内层残留VLAN 20标签的帧发送到链路上。

4. **第二台交换机的Trunk端口**收到该帧，解析出帧中携带的VLAN 20标签，将其视为合法的802.1Q Tag，在VLAN 20内泛洪/转发。攻击成功跨越了VLAN边界。

> **攻击成立的根本原因**：Native VLAN在Trunk出站时不打Tag，导致帧Payload中的残留内层标签“裸露”出来，被第二台交换机误认为有效标签。

**关键限制**：
- 该攻击**仅单向有效**——目标VLAN 20的回程流量携带VLAN 20标签到达第一台交换机的Access端口时，因VID（20）≠ PVID（1）而被丢弃；
- 仅当Native VLAN未被修改（即保持VLAN 1）且未启用`vlan dot1q tag native`时成立；
- 攻击者操作系统必须配置VLAN子接口或使用Scapy等工具。

**防御配置（彻底阻断）** ：
```cisco
! 前置条件：确保VLAN 999已创建并激活
vlan 999

! 方案1：修改Native VLAN为非默认值，使攻击者无法同时满足PVID=Native VLAN
interface GigabitEthernet0/24
 switchport trunk native vlan 999

! 方案2：强制Native VLAN帧携带标签（Cisco专用）
vlan dot1q tag native   ! 出站Native VLAN帧带标签，使攻击帧在Trunk链路上不再“裸露”
! 注意：该全局命令与接口级native vlan命令配合时，需确保Native VLAN ID全局一致

! 方案3：Trunk上限制allowed vlan，最小化攻击面
switchport trunk allowed vlan 10,20,30,999
```

**防御验证**：
- 在Trunk端口抓包，Native VLAN帧应显示802.1Q Tag（若`vlan dot1q tag native`已配置）；
- `show interfaces trunk`确认Allowed VLAN列表不含未授权的VLAN。


## 七、VLAN配置安全基线检查清单

| 检查项 | 基线标准 | 验证命令（Cisco） |
|:---|:---|:---|
| 所有Access端口模式 | `switchport mode access` | `show interfaces status \| include access` |
| Access端口DTP协商关闭 | `switchport nonegotiate` | `show interfaces trunk`（确认不在列表中） |
| Trunk Native VLAN | ≠ VLAN 1，推荐999 | `show interfaces trunk` |
| Trunk allowed VLAN | 显式列表，不含VLAN 1 | `show interfaces trunk` |
| Native VLAN标签强制 | `vlan dot1q tag native`启用 | `show running-config \| include dot1q tag native` |
| vSphere VGT模式 | 禁用或限制 | 检查vSwitch端口组配置 |
| 根桥位置（STP） | 固定为核心交换机 | `show spanning-tree root` |


## 八、现代扩展：虚拟化与容器环境下的VLAN

### 8.1 虚拟化环境（VMware vSphere）

| 模式 | 说明 | 安全风险 |
|:---|:---|:---|
| **VST** | vSwitch在VM出口打标签，VM不感知 | 低风险——vSwitch统一控制 |
| **VGT** | VM自身识别和处理VLAN标签 | **高风险**——若VM被攻陷，可修改内部VLAN ID访问其他VLAN |
| **EST** | 物理交换机打标签，vSwitch透传 | 低风险——需物理交换机ACL |

**安全建议**：生产环境强制使用VST模式（在vSphere端口组中设置VLAN ID，选择“VLAN”类型而非“VLAN Trunk”）。禁用VGT模式，或通过vCenter权限限制仅允许特定VM使用VGT。

### 8.2 容器网络

- **MACVLAN驱动**：容器直接使用宿主机物理网卡的子接口接入物理VLAN。
- **风险**：容器逃逸后可发送带VLAN标签的帧，可能实现VLAN跳跃。
- **防御**：限制特权容器运行；若使用MACVLAN，通过CNI配置明确绑定VLAN ID；使用Kubernetes NetworkPolicy限制跨Namespace流量；在宿主机层面通过eBPF或iptables限制VLAN Tagged帧的生成。


## 九、总结

VLAN是现代网络隔离的基石，也是内网渗透中攻击者首要突破的边界。理解802.1Q标签格式、Access/Trunk端口行为、Native VLAN收发双向机制，是构建二层安全防御体系的基础。

攻击者通过DTP协商滥用可将Access端口提升为Trunk，通过构造双层标签帧利用Native VLAN的“出站不打Tag”机制实施Double Tagging注入——但在配置了“强制Access + Native VLAN修改 + `vlan dot1q tag native` + VLAN过滤”的加固网络中，这些攻击均被有效阻断。

**关键认知**：VLAN仅提供二层隔离，一旦启用三层路由（`ip routing`），各VLAN SVI之间默认互通，必须通过**ACL或防火墙策略**显式控制跨VLAN流量。安全隔离是“二层VLAN划分 + 三层ACL控制”的组合产物，缺一不可。

下一步，建议将VLAN知识与MAC地址表、STP、ARP安全串联，构建完整的二层安全知识体系。


## 参考文献与延伸阅读

### 标准与RFC
- IEEE 802.1Q-2022 — *Bridges and Bridged Networks*（含VLAN、STP、MSTP规范）
- IEEE 802.1ad-2005 — *Provider Bridges*（QinQ）
- IEEE 802.1AX-2020 — *Link Aggregation*（EtherChannel）

### 工程文档
- Cisco Catalyst 3850/9300 VLAN Configuration Guide, IOS XE Release 16.x
- VMware vSphere Networking — VLAN Tagging Modes（VST/VGT/EST）
- Kubernetes Calico CNI — VLAN/VXLAN配置指南
- MITRE ATT&CK — [T1557: Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)

---

*本文修订于2026年8月，基于Cisco IOS 15.0(2)SE / IOS XE 16.12.01环境验证。VLAN行为因厂商及芯片型号存在差异，生产环境请以具体设备官方文档为准。*
