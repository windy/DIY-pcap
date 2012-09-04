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
      @live.break_loop
    end
    
    def notify_recv_pkt(pkt)
      @watchers.each do |watcher|
        watcher.recv_pkt(pkt)
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
      pkt = @offline.next
      raise EOFError, " no pkt to send" unless pkt
      pkt = pkt.copy
      yield(pkt.body) if block_given?
      #~ #TODO: 分析发送的包还是接受的包
      recv_pkt = @offline.next
      if recv_pkt
        @m.synchronize {
          @expect_recv_queue << recv_pkt.copy.body
        }
      end
      puts 'next'
      pkt.body
    end
    alias_method :next, :next_send_pkt
    
    def do_loop(&block)
      raise "Must give me block" unless block_given?
      while(true) do 
        next_send_pkt(&block)
        sleep 10
      end
    end
    
    def wait_until( timeout = 3, &block )
      timeout(timeout) do
        loop do
          break if block.call
          sleep 1
        end
      end
    end
    
  end
  
  # 这个策略是一个最基本的: 
  # 1. 包必须按期望返回
  # 2. 按顺序返回
  class BasicStrategy
    def initialize(queue)
      @queue = queue
    end
    
    def recv_pkt(pkt)
      # do something with queue and pkt
      # this is a simple example
      # just check equal
      puts 'recv pkt...'
      if pkt == @queue.peek
        puts "pkt same: "
        @queue.pop
      end
    end
  end
  
  DEFAULT_STRATEGY = BasicStrategy
  require 'logger'
  class Controller
    def initialize(live, offline, strategy = DEFAULT_STRATEGY )
      @live = live
      @queue = DIY::Queue.new(offline)
      @strategy = strategy.new(@queue)
      
      @recver = Recver.new(@live)
      @recver.add_watcher(@strategy)
      @recver_t = nil
      @sender = Sender.new(@live)
      
      @logger = Logger.new(STDOUT)
    end
    attr_accessor :logger
    
    def run
      @recver_t = Thread.new do
        @recver.run
      end
      
      #~ @recver_t.join
      
      begin
        @queue.do_loop do |pkt|
          puts 222
          #~ @sender.inject(pkt)
          #~ sleep 2
        end
      rescue EOFError
        @recver.stop
      end
      
    end
    
  end
  
end

if $0 == __FILE__
  require 'rubygems'
  require 'ffi-pcap'
  @device_name = FFI::PCap.dump_devices[0][0]
  live = FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::CopyHandler, :promisc => true)
  #~ live2 = FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
  offline = FFI::PCap::Offline.new('../../simple/pcaps/gre.pcap')
  controller = DIY::Controller.new(live, offline) 
  controller.run
end