DIY-pcap
=============

## 这是什么?

自定义发包工具,可以轻易实现包交互, 实现是来自 [ffi-pcap](https://github.com/sophsec/ffi-pcap/) 的二次封装.

## 使用方法,完全自定义发包 ( 一 )

1. 安装很简单

    ```bash
  gem install DIY-pcap
```
        
    服务端与本机需要同时安装.
        
2. 准备好要发送和接收的数据放在 `pcaps` 目录下, 创建文件 spec.rb:

    ```ruby
pcap do |s|
      s.dir = "pcaps"
      s.send "r1.dat"
      s.recv "s1.dat"
      s.recv "s2.dat"
      s.send "r2.dat"
end
```
        
    上面的意思是, 从本机发送 `r1.dat` 到 服务端, 并等待接收 `s1.dat`, `s2.dat` 数据包, 之后再发送 `r2.dat`, 最后结束.
    更多内容请参考: simple/ 里面的内容.

3. 开始发送与接收数据

  * 服务端,执行 `rpcap -f spec.rb`
  
  * 本机, 执行 `pcap -f spec.rb`
  
## 使用方法, 回放pcap报文 ( 二 )

1. 安装同上

2. 准备好 pcap 文件放在 `pcaps/simple.pcap` 目录下, 创建文件 spec.rb:

    ```ruby
require 'rubygems'
require 'diy-pcap'
DIY::Builder.new do
      pcapfile "pcaps/simple.pcap"
      use DIY::SimpleStrategy.new
      client "x.x.x.x" # 配置客户端ip, 缺省端口为7878
      server "x.x.x.x" # 配置服务端ip, 缺省端口为7879
      me "x.x.x.x" # 配置控制端ip, 缺省端口为7880, 以上都可以写为 x.x.x.x:x 的形式, 与 rpcap或pcap的 -i 参数对应
end
    ```
3. 使用方法( 准备三台主机或逻辑主机, 只是试验的话可以使用 `127.0.0.1` )

  开始前建议重起服务端与客户端.
  * 服务端, 执行 `rpcap` ( 如果启动出错, 请参考 rpcap -h 中参数 -i 与 -n )
  * 客户端, 执行 `pcap` ( 如果启动出错, 请参考 pcap -h 中参数 -i 与 -n )
  * 控制端, 执行 `ruby spec.rb`, OK, 开始交互, 结束后, 会有 cost time 与 fail count 输出.


4. (其他说明) 扩展策略, 自定义日志, 修改报文内容参见 [Wiki Home](/windy/DIY-pcap/wiki).
  
OK, 一切如故.