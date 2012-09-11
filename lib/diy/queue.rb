require 'thread'
require 'timeout'
module DIY
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
      timeout(timeout, DIY::HopePacketTimeoutError.new("hope packet wait timeout after #{timeout} senconds") ) do
        loop do
          break if block.call
          sleep 0.01
        end
      end
    end
    
  end # end Queue
end