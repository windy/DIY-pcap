DIY-pcap
=============

## 这是什么?

自定义发包工具,可以轻易实现包交互, 实现是来自 [ffi-pcap](https://github.com/sophsec/ffi-pcap/) 的二次封装.

## 使用方法

1. 安装很简单

    ```
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

  * 服务端,执行 `rpcap spec.rb`
  
  * 本机, 执行 `pcap spec.rb`
  
OK, 祝你好运.