require 'ffi/pcap'
require 'logger'
require 'diy/version'
module DIY
  class PCAP
    def initialize
      @timeout = 10
      @dir = Dir.pwd
      @pkt_stack = []
      @device_name = FFI::PCap.dump_devices[0][0]
      yield self
      @driver = FFI::PCap::Live.new(:dev=>@device_name, :handler => FFI::PCap::Handler, :promisc => true)
      #~ pause_for_user
      run
    end
    
    attr_accessor :timeout, :dir, :device_name
    
    def send(pkt_dir)
      @pkt_stack << PacketEx.new( pkt_dir2pkt(pkt_dir), PacketEx::SEND)
    end
    
    def recv(pkt_dir)
      @pkt_stack << PacketEx.new( pkt_dir2pkt(pkt_dir), PacketEx::RECV)
    end
    
    def pkt_dir2pkt(dir)
      File.read( File.join( @dir, dir ) )
    end
    
    def run
      if $SERVER
        run_server
      else
        run_client
      end
    end
    
    def pause_for_user
      puts "Input ENTER for going..."
      gets
    end
    
    def run_client
      @pkt_stack.each do |pkt|
        if pkt.to_outer?
          send_pkt(pkt.pkt)
        else
          recv_pkt(pkt.pkt)
        end
      end
    end
    
    def run_server
      @pkt_stack.each do |pkt|
        if pkt.to_inner?
          send_pkt(pkt.pkt)
        else
          recv_pkt(pkt.pkt)
        end
      end
    end
    
    def send_pkt(pkt)
      sleep 1
      logger.info("send pkt: [ #{Time.now} ]#{pkt[0..10].dump}...")
      @driver.inject(pkt)
    end
    
    def recv_pkt(pkt)
      if pkt.size < 60
        logger.info "pkt size #{pkt.size} less than 60, fill with zero"
        pkt += "0" * (60 - pkt.size)
      end
      logger.info("I hope pkt: #{pkt[0..10].dump}")
      @driver.loop do |this, new_pkt|
        #~ logger.info("recv pkt: [ #{new_pkt.time} ]: #{new_pkt.body[0..10].dump}..." )
        if new_pkt.body == pkt
          logger.info("recv pkt: [ #{new_pkt.time} ]: #{new_pkt.body[0..10].dump}..." )
          logger.info "got the same pkt,stop"
          return true
        end
      end
    end
    
    def logger
      @@logger ||= DIY::Logger
    end
    
    def logger=(logger)
      @@logger = logger
    end
    
  end
  
  class PacketEx
    SEND = 1
    RECV = 0
    def initialize( pkt, pos )
      @pkt = pkt
      @pos = pos
    end
    
    def to_outer?
      @pos == SEND
    end
    
    def to_inner?
      @pos == RECV
    end
    
    attr_reader :pkt, :pos
  end
end