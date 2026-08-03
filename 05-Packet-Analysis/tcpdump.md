### 1. 定义与底层原理
- **全称**：**TCP Dump**。它本质上是利用操作系统提供的 **PF_PACKET** (Linux) 或 **BPF** (Berkeley Packet Filter，BSD包过滤器) 机制，在数据链路层（L2）进行原始套接字(raw socket)捕获。
- **与Wireshark的关系**：tcpdump负责抓取和保存为`.pcap`文件，Wireshark负责读取和分析。绝佳组合是 **“服务器上用tcpdump抓，拖回本地用Wireshark看”**。
- **运行权限**：抓包需要访问网卡的底层接口，**必须使用 `sudo` 或以 root 身份运行**。

### 2. 核心语法结构（记住这个骨架）
tcpdump的命令行逻辑分为三部分，缺一不可：
```bash
sudo tcpdump [选项参数] [过滤表达式]
```
- **选项参数**：控制“怎么抓”（如输出格式、写入文件）。
- **过滤表达式**：控制“抓什么”（这是核心，基于BPF语法）。

### 3. 必知必会的核心参数（选项）
在实战中，真正高频使用的参数只有下面这几个：

| 参数 | 全称/含义 | 实战用途（为什么这么设） |
| :--- | :--- | :--- |
| **`-i`** | interface | 指定网卡。**必填**。常用 `-i eth0` 或 `-i any`（抓所有网卡，但在高流量服务器上慎用，CPU会飙高）。 |
| **`-n`** | numeric | **不解析IP地址和端口为域名**。**极其重要！** 加上它，tcpdump就不会发DNS反向查询，抓包速度会快10倍以上，且避免DNS污染干扰。 |
| **`-nn`** | numeric port & host | 同时不解析主机名和端口名（即不把80显示为`http`）。抓生产环境必加。 |
| **`-s`** | snaplen (snapshot length) | 抓取每个包的前多少字节。默认是262144字节（新版）或65535。**抓取完整应用层数据**建议设为 `-s 0`（自动抓取完整包）。 |
| **`-c`** | count | 抓到指定数量的包后自动退出。用于快速采样，防止磁盘写爆。 |
| **`-w`** | write | **写入文件**（`.pcap`格式）。这是最稳妥的做法，不占用终端输出，方便后续分析。 |
| **`-r`** | read | 读取之前保存的`.pcap`文件进行离线分析。 |
| **`-A`** | ASCII | 以ASCII码显示包内容（适合看HTTP明文请求）。 |
| **`-X`** | hex & ASCII | 以十六进制和ASCII显示（适合看二进制协议或底层标志位）。 |

---

### 4. BPF过滤表达式（核心中的核心）
这是你问的 **“如何抓取我想要的数据包”** 的精确答案。BPF语法分为三个维度：**类型 + 方向 + 协议**，并用逻辑词组合。

#### 第一类：主机过滤（盯死某个IP）
```bash
# 抓取所有与 192.168.1.100 通信的包（双向）
sudo tcpdump -i eth0 -nn host 192.168.1.100

# 只抓 192.168.1.100 发送出去的包（源地址）
sudo tcpdump -i eth0 -nn src host 192.168.1.100

# 只抓发往 192.168.1.100 的包（目的地址）
sudo tcpdump -i eth0 -nn dst host 192.168.1.100
```

#### 第二类：端口过滤（盯死某个服务）
```bash
# 抓所有与 80 端口相关的双向流量
sudo tcpdump -i eth0 -nn port 80

# 抓源端口是 443 的包（即服务器响应的HTTPS流量）
sudo tcpdump -i eth0 -nn src port 443

# 抓目的端口是 53 的包（即发出去的DNS查询请求）
sudo tcpdump -i eth0 -nn dst port 53

# 抓端口范围（1-1024 的特权端口）
sudo tcpdump -i eth0 -nn portrange 1-1024
```

#### 第三类：协议过滤（盯死某种协议）
直接写协议名即可，它会匹配IP头部中的Protocol字段。
```bash
# 只抓 ICMP 包（ping）
sudo tcpdump -i eth0 -nn icmp

# 只抓 TCP 包
sudo tcpdump -i eth0 -nn tcp

# 只抓 UDP 包
sudo tcpdump -i eth0 -nn udp
```

#### 第四类：TCP标志位过滤（攻防核心！）
这是渗透测试和排查连接问题最常用的技巧。tcpdump能直接过滤`tcpflags`。

```bash
# 抓所有 SYN 包（常用于检测端口扫描或查看新建连接）
sudo tcpdump -i eth0 -nn "tcp[tcpflags] & tcp-syn != 0"

# 抓所有 RST 包（常用于查看谁在异常中断连接，攻击者常用RST劫持）
sudo tcpdump -i eth0 -nn "tcp[tcpflags] & tcp-rst != 0"

# 抓 SYN+ACK 包（三次握手的第二次，确认服务端是否在响应）
sudo tcpdump -i eth0 -nn "tcp[tcpflags] == tcp-syn|tcp-ack"

# 抓只含ACK但没有数据载荷的纯确认包（可能表示空响应或心跳）
```

#### 第五类：高级组合逻辑（逻辑词：`and` / `or` / `not`，括号必须用引号）
```bash
# 复杂场景：抓取来自 10.0.0.2，发往任意主机的 443 端口，且不是发往 8.8.8.8 的包
sudo tcpdump -i eth0 -nn "src host 10.0.0.2 and dst port 443 and not dst host 8.8.8.8"

# 抓取 HTTP 的 GET 请求（利用深度包检测，偏移量过滤）
# 解析：tcp[12:4] 表示从TCP头部偏移12字节处取4字节，值为 0x47455420 即 "GET "
sudo tcpdump -i eth0 -nn -A "tcp dst port 80 and tcp[12:4] = 0x47455420"
```

---

### 5. 实战流程：从生手到老手的标准三步走

新手喜欢直接用 `-A` 看实时输出，老手（我）永远遵循 **“先存后看”** 原则，避免影响正在运行的服务。

**第一步：后台抓取存文件**
```bash
# 参数解析：
# -i any: 抓所有网卡
# -nn: 不解析域名
# -s 0: 抓完整包
# -c 1000: 抓1000个包后自动停（防止文件过大）
# -w /tmp/capture.pcap: 写入文件
sudo tcpdump -i any -nn -s 0 -c 1000 -w /tmp/capture.pcap
```

**第二步：传输到本地（使用SCP）**
```bash
# 在本地电脑执行，把服务器上的抓包文件拉下来
scp user@your_server_ip:/tmp/capture.pcap ./
```

**第三步：拖进Wireshark分析**
用Wireshark打开`capture.pcap`，利用图形化界面精确过滤应用层数据。**这是最专业、最安全的生产环境抓包姿势。**

---

### 6. 安全视角：实战中的两个救命场景

**场景一：服务器疑似被DDoS流量攻击，CPU飙高**
不要盲目抓包，先通过`iftop`或`nethogs`看到异常IP，然后精准狙击：
```bash
# 只抓来自攻击IP 5.5.5.5 的包，只抓100个，快速分析攻击特征
sudo tcpdump -i eth0 -nn -c 100 src host 5.5.5.5 -w attack_sample.pcap
```

**场景二：排查“为什么我的curl请求报500错误”**
我们想看到完整的HTTP请求和响应头。
```bash
# -A 显示ASCII内容，-vv 显示更详细的时间戳
sudo tcpdump -i lo -nn -A -vv "tcp port 8080"
```
（注意：如果是本机服务通信，网卡要选`-i lo`即回环接口）。

---

### 7. 老工程师的避坑指南（血的教训）
1.  **慎用 `-i any`**：在万兆网络中，`any`模式会复制所有接口流量，CPU负载直接爆表。**务必指定具体网卡**（`-i eth0`）。
2.  **记得加 `-n`**：如果不加，tcpdump会尝试反向DNS查询每一个陌生IP，导致抓包卡顿并产生额外DNS流量污染分析结果。
3.  **磁盘空间预警**：在高并发业务下，10分钟就能抓出几十GB的包。**永远加 `-c` 数量限制** 或配合 `timeout` 命令：
   ```bash
   timeout 60 sudo tcpdump -i eth0 -nn -w /tmp/1min_cap.pcap
   ```
4.  **权限问题**：如果普通用户执行提示“Operation not permitted”，记得加上`sudo`，并将当前用户加入`pcap`组。
