# encoding : utf-8
module DIY
  
  class Error < RuntimeError; end
  # 数据包读取完毕
  class EOFError < Error; end

  class Recver
    def initialize(live)
      @live = live
      @watchers = []
    end
    
    def run
      @live.loop do |this, pkt|
        notify_recv_pkt(pkt)
      end
    end
    
    def stop
      @live.stop
    end
    
    def notify_recv_pkt(pkt)
      @watchers.each do |watcher|
        watcher.recv_pkt(pkt.body)
      end
    end
    
    def add_watcher(watcher)
      @watchers = [] unless @watchers
      @watchers << watcher
    end
    
    def del_watcher(watcher)
      @watchers.delete(watcher)
    end
  end
  
  class Sender
    def initialize(live)
      @live = live
    end
    
    def inject(pkt)
      puts "send: #{Time.now}"
      @live.inject(pkt)
    end
  end
  
  require 'thread'
  require 'timeout'
  class Queue
    
    def initialize(offline)
      @expect_recv_queue = []
      @offline = offline
      @m = Mutex.new
      # 暂存 next_send_pkt 数据
      @tmp_send_pkt = nil
    end
    
    def expect_recv_queue
      @expect_recv_queue
    end
    
    def pop
      return nil if @expect_recv_queue.empty?
      @m.synchronize {
        return @expect_recv_queue.shift
      }
    end
    
    def delete(what)
      if @expect_recv_queue.include?(what)
        @m.synchronize {
          if @expect_recv_queue.include?(what)
            return @expect_recv_queue.delete(what)
          end
        }
      end
      return nil
    end
    
    def delete_at(index)
      @m.synchronize {
        return @expect_recv_queue.delete_at(index)
      }
    end
    
    def peek
      return nil if @expect_recv_queue.empty?
      @expect_recv_queue[0]
    end
    
    # 处理发送报文
    #
    # 等待接受报文完成后, 返回发送报文, 并重新填充接受报文
    # TODO: 支持多个pcap文件
    def next_send_pkt(&block)
      wait_until { @expect_recv_queue.empty? }
      if @tmp_send_pkt
        pkt = @tmp_send_pkt
        @tmp_send_pkt = nil
      else
        pkt = write_recv_pkt
        wait_until { @expect_recv_queue.empty? }
      end
      raise EOFError, " no pkt to send" unless pkt
      pkt = pkt.copy
      
      recv_pkt = write_recv_pkt
      
      yield(pkt.body) if block_given?
      
      @tmp_send_pkt = recv_pkt.copy if recv_pkt
      pkt.body
    end
    alias_method :next, :next_send_pkt
    
    def write_recv_pkt
      while ( (recv_pkt = @offline.next) && ( set_first_gout(recv_pkt.body); comein?(recv_pkt.body) ) )
        @m.synchronize {
          @expect_recv_queue << recv_pkt.copy.body
        }
      end
      recv_pkt
    end
    
    def do_loop(&block)
      raise "Must give me block" unless block_given?
      while(true) do 
        next_send_pkt(&block)
      end
    end
    
    def set_first_gout(pkt)
      return @src_mac if @src_mac
      if pkt.size < 12
        raise PktError,"can't find src mac: error format packet"
      end
      @src_mac = pkt[6..11]
    end
    
    def comein?(pkt)
      ret = judge_direct(pkt) do | pkt_mac, src_mac|
        (pkt_mac != src_mac) ^ server?
      end
      ret
    end
    
    def gout?(pkt)
      judge_direct(pkt) do | pkt_mac, src_mac|
        (pkt_mac == src_mac) ^ server?
      end
    end
    
    def server?
      $SERVER
    end
    
    def judge_direct(pkt,&block)
      if pkt.size < 12
        raise PktError,"can't find src mac: error format packet"
      end
      raise "src_mac not set" unless @src_mac
      yield( pkt[6..11], @src_mac )
    end
    
    def wait_until( timeout = 20, &block )
      timeout(timeout) do
        loop do
          break if block.call
          sleep 0.01
        end
      end
    end
    
  end
  
  # 这个策略是一个最基本的: 
  # 具体返回值含义见 @BasicStrategy
  class Strategy
    OK = true
    OK_NO_POP = 1
    FAIL = false
    NONE = nil
  end
  
  class BasicStrategy < Strategy
    
    # @argument:
    # hope_pkt: 期望的报文
    # recv_pkt: 接收的报文
    # queue: 期望接收队列, 如果期望乱序时,你可以使用这个参数
    # 
    # @return: 
    # OK : 匹配, 可以进行下一个报文的处理
    # OK_NO_POP: 匹配了接收队列中的报文, 但是不需要框架自动pop掉期望报文( 注意, 你需要自行处于报文 )
    # FAIL: 肯定失败时使用
    # NONE: 不匹配, 让框架进行下一个报文匹配
    def call(hope_pkt, recv_pkt, queue)
      raise "write code here"
    end
  end
  
  class SimpleStrategy < BasicStrategy
    def call(hope_pkt, recv_pkt, queue)
      if hope_pkt == recv_pkt
        return OK
      else
        return NONE
      end
    end
  end
  
  require 'logger'
  class StrategyBuilder
    def initialize(queue)
      @ins = []
      @logger = Logger.new(STDOUT)
      @queue = queue
    end
    attr_reader :queue
    
    def add(strategy)
      @ins << strategy
    end
    alias << add
    
    def logger=(logger)
      @logger = logger
    end
    
    def logger
      @logger
    end
    
    def recv_pkt(pkt)
      recv_pkt_queue(queue,pkt)
    end
    
    def recv_pkt_queue(queue, recv_pkt)
      hope_pkt = queue.peek
      logger.debug("recv_pkt, I hope: #{ hope_pkt[0..10].dump rescue nil }...")
      return if hope_pkt.nil?
      @ins.each do |strategy|
        begin
        ret = strategy.call(hope_pkt, recv_pkt, queue)
        rescue Exception => e
          logger.error("strategy call exception: #{e.class} -> #{e.message}")
          raise
          #仅仅忽略
        else
          if ret == Strategy::OK
            logger.info("pkt same:")
            queue.pop
            return
          elsif ret == Strategy::OK_NO_POP
            logger.info("pkt same but no pop:")
            return
          elsif ret == Strategy::FAIL
            logger.warn("pkt fail:")
          elsif ret == Strategy::NONE
            logger.debug("pkt jumpped:")
            next
          end
        end
      end
    end
  end
  

  class Controller
    def initialize(live, offline, strategy)
      @live = live
      @recver = Recver.new(@live)
      @recver.add_watcher(strategy)
      @recver_t = nil
      @sender = Sender.new(@live)
      @queue = strategy.queue
      @logger = Logger.new(STDOUT)
    end
    attr_accessor :logger
    
    def run
      @recver_t = Thread.new do
        @recver.run
      end
      
      begin
        @queue.do_loop do |pkt|
          @sender.inject(pkt)
        end
        @recver_t.join
      rescue EOFError
        @recver.stop
      end
    end
    
  end
  
  class Builder
    def initialize(&block)
      @strategies = []
      instance_eval(&block)
    end
    
    def find_device
      @device_name ||= FFI::PCap.dump_devices[0][0]
      @live = FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
    end
    
    def device(name)
      @device_name = name
    end
    
    def use(what)
      @strategies.unshift(what)
    end
    
    def pcapfile(pcaps)
      @offline = FFI::PCap::Offline.new(pcaps)
    end
    
    def run
      @offline ||= FFI::PCap::Offline.new('pcaps/example.pcap')
      @queue = Queue.new(@offline)
      @strategy_builder = DIY::StrategyBuilder.new(@queue)
      @strategies.each { |builder| @strategy_builder.add(builder) }
      find_device
      controller = Controller.new( @live, @offline, @strategy_builder )
      controller.run
    end
    
  end
end