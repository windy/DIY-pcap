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
      @pkt_stack << PacketEx.new( pkt_dir2pkt(pkt_dir), PacketEx::SEND, pkt_dir)
    end
    
    def recv(pkt_dir)
      @pkt_stack << PacketEx.new( pkt_dir2pkt(pkt_dir), PacketEx::RECV, pkt_dir)
    end
    
    def pkt_dir2pkt(dir)
      #~ File.read( File.join( @dir, dir ) )
      ret = ""
      File.open( File.join( @dir, dir), "rb") do |f|
        ret += f.read(65535) until f.eof?
      end
      ret
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
          send_pkt(pkt)
        else
          recv_pkt(pkt)
        end
      end
    end
    
    def run_server
      @pkt_stack.each do |pkt|
        if pkt.to_inner?
          send_pkt(pkt)
        else
          recv_pkt(pkt)
        end
      end
    end
    
    def send_pkt(pkt)
      sleep 1
      logger.info("send pkt: [ #{Time.now} ]#{pkt.pkt[0..10].dump}(file: #{pkt.filename}, size: #{pkt.size})...")
      pkt = pkt.pkt
      pkt = fill60(pkt)
      @driver.send_packet(pkt)
    end
    
    def recv_pkt(pkt)
      logger.info("I hope pkt: #{pkt.pkt[0..10].dump}(file: #{pkt.filename}, size: #{pkt.size})...")
      pkt = pkt.pkt
      pkt = fill60(pkt)
      @driver.loop do |this, new_pkt|
        #~ logger.info("recv pkt: [ #{new_pkt.time} ]: #{new_pkt.body[0..10].dump}..." )
        new_pkt_body = fill60(new_pkt.body)
        if new_pkt_body == pkt
          logger.info("recv pkt: [ #{new_pkt.time} ]: #{new_pkt_body[0..10].dump}..." )
          logger.info "got the same pkt,next"
          return true
        end
      end
    end
    
    def fill60(pkt)
      if pkt.size < 60
        logger.debug "pkt size #{pkt.size} less than 60, fill with zero"
        pkt += "0" * (60 - pkt.size)
      end
      pkt
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
    def initialize( pkt, pos, filename = nil )
      @pkt = pkt
      @pos = pos
      @filename = filename
    end
    
    def to_outer?
      @pos == SEND
    end
    
    def to_inner?
      @pos == RECV
    end
    
    def size
      @pkt.size
    end
    
    attr_reader :pkt, :pos, :filename
  end
end