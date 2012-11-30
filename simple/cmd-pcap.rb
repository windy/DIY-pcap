# encoding : utf-8
# 这是一个单个包交互发送的例子
# 安装 DIY-pcap 后, 先启动服务端 `rpcap -f cmd-pcap`, 服务端会开始等待接收包文.
# 启动客户端 `pcap -f cmd-pcap`
# 等待收包完成, 如果出现超时, 说明中间数据不一致, 被修改了.

pcap do |s|  
  s.dir = 'pcaps'
  s.send("r1.dat")
  s.recv("s1.dat")
  s.recv("s2.dat")
  s.recv("s3.dat")
  s.send("r3.dat")
end