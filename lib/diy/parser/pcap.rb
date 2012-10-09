# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

$LOAD_PATH.unshift File.dirname(__FILE__)

require 'socket'
require 'stringio'
require 'mu/fixnum_ext'

module Mu

class Pcap
    class ParseError < StandardError ; end

    LITTLE_ENDIAN = 0xd4c3b2a1
    BIG_ENDIAN    = 0xa1b2c3d4

    DLT_NULL      = 0
    DLT_EN10MB    = 1
    DLT_RAW       = 12 # DLT_LOOP in OpenBSD
    DLT_LINUX_SLL = 113

    attr_accessor :header, :pkthdrs
    
    def initialize
        @header = Header.new
        @pkthdrs = []
    end

    # Read PCAP file from IO and return Mu::Pcap.  If decode is true, also
    # decode the Pkthdr packet contents to Mu::Pcap objects.
    def self.read io, decode=true
        pcap = Pcap.new
        pcap.header = each_pkthdr(io, decode) do |pkthdr|
            pcap.pkthdrs << pkthdr
        end
        return pcap
    end

    # Create PCAP from list of packets.
    def self.from_packets packets
        pcap = Pcap.new
        packets.each do |packet|
            pkthdr = Mu::Pcap::Pkthdr.new
            pkthdr.pkt = packet
            pcap.pkthdrs << pkthdr
        end
        return pcap
    end

    # Write PCAP file to IO.  Uses big-endian and linktype EN10MB.
    def write io
        @header.write io
        @pkthdrs.each do |pkthdr|
            pkthdr.write io
        end
    end

    # Read PCAP packet headers from IO and return Mu::Pcap::Header.  If decode
    # is true, also decode the Pkthdr packet contents to Mu::Pcap objects.  Use
    # this for large files when each packet header can processed independently
    # - it will perform better.
    def self.each_pkthdr io, decode=true
        header = Header.read io
        while not io.eof?
            pkthdr = Pkthdr.read io, header.magic
            if decode
                pkthdr.decode! header.magic, header.linktype
            end
            yield pkthdr
        end
        return header
    end

    # Read packets from PCAP
    def self.read_packets io, decode=true
        packets = []
        each_pkthdr(io) { |pkthdr| packets << pkthdr.pkt }
        return packets
    end

    # Assertion used during Pcap parsing
    def self.assert cond, msg
        if not cond
            raise ParseError, msg
        end
    end

    # Warnings from Pcap parsing are printed using this method.
    def self.warning msg
        $stderr.puts "WARNING: #{msg}"
    end

    def == other
        return self.class == other.class &&
            self.header   == other.header &&
            self.pkthdrs  == other.pkthdrs
    end
end

end

require 'mu/pcap/header'
require 'mu/pcap/pkthdr'
require 'mu/pcap/packet'
require 'mu/pcap/ethernet'
require 'mu/pcap/ip'
require 'mu/pcap/ipv4'
require 'mu/pcap/ipv6'
require 'mu/pcap/tcp'
require 'mu/pcap/udp'
require 'mu/pcap/sctp'
