# encoding : utf-8
require 'diy/packet'
require 'drb'
require 'thread'

module DIY
  class Worker
    
    include DRbUndumped
    
    def initialize(live)
      @live = live
      @recv_t = nil
      @start = false
      @queue = Queue.new
      @running = false
      loop_recv
      loop_callback
    end
  
    # 发包
    def inject(pkts)
      pkts.each do |pkt|
        DIY::Logger.info "send pkt: #{pkt.pretty_print}"
        @live.send_packet(pkt.content)
      end
    end
    
    def loop_recv
      @recv_t = Thread.new do
        DIY::Logger.info "start thread recving pkt..."
        @live.loop do |this, pkt|
          if ! @start
            DIY::Logger.debug "looprecv stop..." unless @recv_stop_flag
            @recv_stop_flag = true
            next
          end
          next unless pkt
          @queue.push(pkt.body)
        end
        DIY::Logger.debug "worker: stopped loop recv"
      end
    end
    
    def loop_callback
      @running = true
      @callback_t = Thread.new do 
        #~ DIY::Logger.info "start thread callbacking pkt..."
        while @running do
          if ! @start
            DIY::Logger.debug "callback stop..." unless @callback_stop_flag
            @callback_stop_flag = true
            sleep 0.01
            next
          end        
          begin
            pkt = @queue.pop
            #~ DIY::Logger.info "callback: #{pkt}"
            
            if @block and pkt
              @block.call(pkt)
            end
          rescue DRb::DRbConnError
            DIY::Logger.info "closed connection by controller"
            @start = false
            @queue.clear
          rescue RangeError=>e
            DIY::Utils.print_backtrace(e)
            raise e
          end
        end
        DIY::Logger.debug "stopped loop callback"
      end
    end
    
    #收包
    def ready(&block)
      stopping
      DIY::Logger.info("start recv pkt")
      @block = block
      start
    end
    
    # 停止收发
    def terminal
      DIY::Logger.info("stop recv pkt")
      stopping
    end
    
    # 停止线程
    def stop
      @running = false
      pause
      @live.break
      Utils.wait_until { @recv_t && ! @recv_t.alive? }
      Utils.wait_until { @callback_t && ! @callback_t.alive? }    
    end
    
    # 过滤器
    def filter(reg)
      @live.set_filter(reg)
    end
    
    def inspect
      "<Worker: #{@live.net}>"
    end
    
    private
    def stopping
      pause
      while ! paused?
      end
      DIY::Logger.debug "stop success"
    end
    
    def pause
      DIY::Logger.debug "pausing..."
      @start = false
      @recv_stop_flag = false
      @callback_stop_flag = false
      @queue.clear
      @queue.push nil
    end
    
    def start
      @start = true
    end
    
    def paused?
      ! @start and recv_stop? and callback_stop?
    end
    
    def recv_stop
      @recv_stop_flag = true
    end
    
    def recv_stop?
      @recv_stop_flag
    end
    
    def callback_stop
      @callback_stop_flag = true
    end
    
    def callback_stop?
      @callback_stop_flag
    end
  
  end
end