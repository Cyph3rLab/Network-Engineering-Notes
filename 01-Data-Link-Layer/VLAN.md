# VLAN虚拟局域网深度解析：从802.1Q原理到二层隔离与攻击防御实战

> **实验环境**：Cisco Catalyst 3850（IOS XE 16.12）/ Cisco 2960（IOS 15.0(2)）/ VMware vSphere 8.0 / Kubernetes 1.28（Calico CNI）/ Kali Linux 2025.1（yersinia 0.7.3、scapy 2.5.0）
>
> **合规声明**：本文所有攻击技术描述仅用于网络安全防护研究与授权环境下的安全测试。未经书面授权的网络攻击行为违反《中华人民共和国网络安全法》及《刑法》第285/286条，切勿用于非法目的。

## 一、VLAN的基本概念

VLAN（Virtual Local Area Network，虚拟局域网）是一种在物理交换机上划分多个逻辑独立网络的技术。在没有VLAN的环境中，所有设备同属一个广播域；引入VLAN后，虽然设备物理上连接在同一台交换机，逻辑上却相当于处于不同的交换机之中，广播流量被有效隔离。

> **规范来源**：IEEE 802.1Q-2014 “Bridges and Bridged Networks”。

## 二、VLAN的核心应用价值

| 价值维度 | 说明 |
|:---|:---|
| **隔离广播域** | 大规模网络通过VLAN划分，各域广播互不干扰，避免广播风暴消耗带宽和CPU。 |
| **提升网络安全** | 不同VLAN默认无法二层通信。但需注意：**VLAN隔离仅作用于二层，若配置VLAN间路由（SVI），仍需依赖ACL或防火墙实现安全边界。** |
| **简化网络管理** | 物理搬迁时无需重新布线，仅需调整端口所属VLAN。 |

## 三、VLAN的协议定位与802.1Q标签结构

VLAN工作在OSI模型的**数据链路层（第二层）**。802.1Q标准在以太网帧头中插入一个4字节的标签字段，位于源MAC地址和EtherType/长度字段之间。

```
┌──────────┬──────────┬──────────┬──────────┬──────────┬────────────┐
│  Dst MAC │  Src MAC │ 802.1Q   │ EtherType│ Payload  │    FCS     │
│  (6B)    │  (6B)    │  Tag(4B) │  (2B)    │(46-1500B)│  (4B)      │
└──────────┴──────────┴──────────┴──────────┴──────────┴────────────┘
                          │
                          ▼
               ┌──────────┬─────────────────────┐
               │  TPID    │        TCI          │
               │  (2B)    │      (2B)           │
               ├──────────┼──────┬──────┬───────┤
               │ 0x8100   │ PCP  │ DEI  │  VID  │
               │ 固定值   │(3bit)│(1bit)│ (12bit)│
               └──────────┴──────┴──────┴───────┘
```

- **TPID**：固定值为`0x8100`。在QinQ（802.1ad）场景中，外层TPID可为`0x88A8`。
- **VID**：12位，取值范围0–4095，可用范围1–4094。
- **VLAN ID规划**：VLAN 1为默认VLAN，1002–1005保留给FDDI/Token Ring。企业规划建议使用2–1001和1006–4094。

## 四、交换机端口模式详解

### 4.1 Access端口
- **特性**：仅属于一个VLAN；终端发送的帧不携带标签；交换机接收时打上内部标识，转发时剥离标签。
- **收到带标签帧行为**：标准Access端口收到携带VLAN标签的帧时默认丢弃（无论是否匹配）。

### 4.2 Trunk端口
- **特性**：允许多个VLAN通过；传输时保留802.1Q标签（Native VLAN除外）。
- **Native VLAN机制**：
  - 发送方向：Native VLAN的帧发出时不携带标签。
  - 接收方向：收到无标签帧时归入Native VLAN。
> ⚠️ 两端Trunk端口的Native VLAN ID必须一致，否则会产生 `%CDP-4-NATIVE_VLAN_MISMATCH` 告警，导致非预期的VLAN穿越。

## 五、VLAN 1的“幽灵风险”与Native VLAN安全加固

### 5.1 为什么VLAN 1极其危险？
1. 所有交换机端口默认属于VLAN 1，Trunk默认允许VLAN 1通过且Native VLAN默认为1。
2. CDP、VTP、DTP等管理协议默认在VLAN 1上传输。即使全局 `shutdown` 了VLAN 1，某些控制协议仍可能在VLAN 1上传输。
3. 攻击者可利用Native VLAN的“无标签”机制注入恶意流量。

### 5.2 生产环境标准配置（双重保护）
```cisco
interface GigabitEthernet0/24
  switchport trunk native vlan 999      ! ① 修改Native VLAN为非默认值
  switchport trunk allowed vlan 10,20,30,999   ! ② 限制允许的VLAN列表
  switchport trunk allowed vlan remove 1        ! ③ 显式拒绝VLAN 1（关键）
```

## 六、攻击手法深度拆解

> ⚠️ **风险提示**：`yersinia` 等工具的高频发包可能导致老款交换机CPU满载宕机，严禁在非隔离实验环境运行。

### 6.1 Switch Spoofing（交换机欺骗）——DTP协议滥用

DTP是Cisco私有协议，用于协商链路是否变为Trunk。模式包括 `dynamic desirable`（主动发起协商）、`dynamic auto`（被动等待）、`trunk`、`access`。注意，不同型号交换机默认DTP模式不同，但不推荐使用dynamic模式。

**攻击原理**：
1. 攻击者接入Access端口，发送伪造的DTP协商帧（模式设为`Desirable`）。
2. DTP报文中不包含“我是交换机”的语义，攻击者仅声明希望建立Trunk。
3. 若目标端口配置为`dynamic auto`或`desirable`，交换机响应该协商，将端口动态切换为Trunk模式。
4. 攻击者随后可通过该Trunk端口访问所有VLAN。

**防御配置**：
```cisco
interface GigabitEthernet0/1
  switchport mode access        ! 强制Access，拒绝DTP协商
  switchport nonegotiate        ! 不发送也不响应DTP帧
```

### 6.2 Double Tagging（双标签攻击）——真实机制详解

该攻击利用了802.1Q Native VLAN在Access端口的剥离机制。

**攻击前提**：攻击者接入的Access端口必须属于Trunk链路的Native VLAN（如默认的VLAN 1）。

**攻击原理**：
1. 攻击者构造并发送一个**带有双层802.1Q标签**的以太网帧：外层标签为VLAN 10（Native VLAN），内层标签为VLAN 20（目标VLAN）。
2. **第一台交换机**的Access端口（PVID=10）收到该帧。根据802.1Q规定，Access端口会剥离与PVID匹配的外层标签。于是，外层VLAN 10标签被剥离，内层VLAN 20标签暴露。
3. 第一台交换机在内部转发该帧。当该帧从Trunk端口发出时，交换机根据暴露出的内层标签（VLAN 20）打上VLAN 20标签发送至链路。
4. **第二台交换机**的Trunk端口收到带有VLAN 20标签的帧，正常解析并在VLAN 20内泛洪，攻击流量成功穿越。

**关键限制**：
- 该攻击是**单向的**。VLAN 20的回程流量携带VLAN 20标签，到达第一台交换机的Access端口时，因VLAN不匹配被丢弃。
- 仅当Native VLAN未被修改，且未启用 `vlan dot1q tag native` 时有效。

**防御配置（彻底阻断）**：
```cisco
! 方案1：修改Native VLAN为非默认值（攻击者无法接入Native VLAN）
interface GigabitEthernet0/24
  switchport trunk native vlan 999

! 方案2：强制Native VLAN帧携带标签（Cisco专有，Access口无法剥离外层标签）
vlan dot1q tag native

! 方案3：Trunk上限制allowed vlan
switchport trunk allowed vlan 10,20,30,999
```

## 七、现代扩展：虚拟化与容器环境下的VLAN

### 7.1 虚拟化环境（VMware vSphere）
| 模式 | 说明 | 安全风险 |
|:---|:---|:---|
| **VST** | vSwitch在VM出口打标签，VM不感知 | 低风险——vSwitch统一控制 |
| **VGT** | VM自身识别和处理VLAN标签 | **高风险**——攻击者可修改VM内VLAN ID访问其他VLAN |
| **EST** | 物理交换机打标签，vSwitch透传 | 低风险——需物理交换机ACL |

**安全建议**：生产环境强制使用VST模式。

### 7.2 容器网络
- **MACVLAN驱动**：容器直接使用宿主机物理网卡的子接口接入物理VLAN。**风险**：容器逃逸后可发送带VLAN标签的帧实现VLAN跳跃。
- **防御**：限制特权容器；若使用MACVLAN，通过CNI配置明确绑定VLAN ID；使用NetworkPolicy限制跨Namespace流量。

## 八、VLAN配置安全基线检查清单

| 检查项 | 基线标准 | 验证命令（Cisco） |
|:---|:---|:---|
| 所有Access端口模式 | `switchport mode access` | `show interfaces status \| include access` |
| Access端口DTP协商关闭 | `switchport nonegotiate` | `show interfaces trunk`（确认不在列表中） |
| Trunk Native VLAN | ≠ VLAN 1，推荐999 | `show interfaces trunk` |
| Trunk allowed VLAN | 显式列表，不含VLAN 1 | `show interfaces trunk` |
| Native VLAN标签强制 | `vlan dot1q tag native`启用 | `show running-config \| include dot1q tag native` |
| vSphere VGT模式 | 禁用或限制 | 检查vSwitch端口组配置 |

## 九、总结

VLAN是现代网络隔离的基石，也是内网渗透中攻击者首要突破的边界。理解802.1Q标签格式、Access/Trunk端口行为、Native VLAN收发双向机制，是构建二层安全防御体系的基础。攻击者通过DTP协商滥用可将Access端口提升为Trunk，通过构造双层标签帧可利用Native VLAN剥离机制实施Double Tagging攻击——但这些攻击在配置了“强制Access + Native VLAN修改 + VLAN过滤”的加固网络中均被有效阻断。下一步，建议将VLAN知识与MAC地址表、STP、ARP安全串联，构建完整的二层安全知识体系。

## 参考文献与延伸阅读

1. **IEEE 802.1Q-2014** — *Bridges and Bridged Networks*
2. **Cisco VLAN Configuration Guide** — Catalyst 3850 Switching Configuration
3. **VMware vSphere Networking** — VLAN Tagging Modes（VST/VGT/EST）
4. **MITRE ATT&CK** — T1557: Adversary-in-the-Middle

---

*本文修订于2026年8月，基于Cisco IOS 15.0(2)/XE 16.12环境验证。VLAN行为因厂商及芯片型号存在差异，生产环境中请以具体设备文档为准。*
