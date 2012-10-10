PCAP parser
=========

## 使用方法

### 解析报文



    ether = Mu::Pcap::Ethernet.from_bytes pkt_str
    
    puts ether.payload
    
  即: 一个报文( 必须是纯字符串 ), 被递归解析, 每个 `payload`  是它上一层的协议类( 比如 `Ethernet`, `IPv4`, `UDP` ), 下面是一些常用的方法:
  
* Ethernet

    * `from_bytes(str)`
    
        解析报文, 并返回特定的类(公共)
    
    * `to_bytes`
      
        重新生成报文, 会重新计算checksum(公共)
    
    * `payload`
    
        负荷, 通俗叫报文内容, 如果还有被支持的上层协议, 则返回相对应的类. 则已经没有, 则返回真正的负荷.(公共)
       
    * `src(=)`, `dst(=)`, `type(=)`
    
        源物理地址, 目的物理地址, 以及上层负载类型( IP, IP6, ARP, PPPOE, 802_1Q )
        

* IPv4

    * `:ip_id`, `:offset`, `:ttl`, `:proto`, `:src`, `:dst`, `:dscp`
    
        标志, 段偏移, 生存期, 上层协议(TCP,UDP, SCTP), 源IP, 目的IP, TOS标记

    * v4?
        
        返回 true
    
    * fragment?
    
        检查是否分片

* IPv6

    * hop_limit
    
    * next_header
    
* TCP

    * `src_port`, `dst_port`, `seq`, `ack`, `flags`, `window`, `urgent`, `mss`, `proto_family`
    
        不一一说明, `flags` 可以直接与 ( `TH_FIN`, `TH_SYN`, `TH_RST`, `TH_PUSH`, `TH_ACK`, `TH_URG`, `TH_ECE`, `TH_CWR`) 相与(&), 以判断标识.
    
* UDP
   
   * `dst_port`, `src_port`

更详细的指导, 请查看 `rdoc`:

在命令行输入 `gem server`, 打开浏览器, 输入 `http://localhost:8808`.
    
## Thanks to:
Fork from : <https://github.com/mudynamics/pcapr-local/tree/master/lib/mu>

Thanks to  mudynamics, github is <https://github.com/mudynamics>