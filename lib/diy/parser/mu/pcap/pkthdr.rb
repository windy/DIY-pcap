# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class Pkthdr
    attr_accessor :endian, :ts_sec, :ts_usec, :caplen, :len, :pkt, :pkt_raw

    def initialize endian=BIG_ENDIAN, ts_sec=0, ts_usec=0, caplen=0, len=0, pkt=nil
        @endian = endian
        @ts_sec = ts_sec
        @ts_usec = ts_usec
        @caplen = caplen
        @len = len
        @pkt = pkt
        @pkt_raw = pkt
    end

    FMT_NNNN = 'NNNN'
    FMT_VVVV = 'VVVV'
    def self.read io, endian=BIG_ENDIAN
        if endian == BIG_ENDIAN
            format = FMT_NNNN
        elsif endian == LITTLE_ENDIAN
            format = FMT_VVVV
        end
        bytes = io.read 16
        if not bytes 
            raise EOFError, 'Missing PCAP packet header'
        end
        if not bytes.length == 16
            raise ParseError, "Truncated PCAP packet header: expected 16 bytes, got #{bytes.length} bytes"
        end
        ts_sec, ts_usec, caplen, len = bytes.unpack format
        pkt = io.read(caplen)
        if not pkt 
            raise ParseError, 'Missing PCAP packet header packet'
        end
        if not pkt.length == caplen
            raise ParseError, "Truncated PCAP packet header: expected #{pkthdr.caplen} bytes, got #{pkthdr.pkt.length} bytes"
        end
        pkthdr = Pkthdr.new endian, ts_sec, ts_usec, caplen, len, pkt
        return pkthdr
    end

    def write io
        if @pkt.is_a? String
            pkt = @pkt
        else
            string_io = StringIO.new
            @pkt.write string_io
            pkt = string_io.string
        end
        len = pkt.length
        bytes = [@ts_sec, @ts_usec, len, len].pack FMT_NNNN
        io.write bytes
        io.write pkt
    end

    def decode! endian, linktype
        @pkt = case linktype
        when DLT_NULL;      Pkthdr.decode_null endian, @pkt
        when DLT_EN10MB;    Pkthdr.decode_en10mb @pkt
        when DLT_RAW;       raise NotImplementedError
        when DLT_LINUX_SLL; Pkthdr.decode_linux_sll @pkt
        else raise ParseError, "Unknown PCAP linktype: #{linktype}"
        end
    end

    # See http://wiki.wireshark.org/NullLoopback
    # and epan/aftypes.h in wireshark code.
    BSD_AF_INET6 = [
        OPENBSD_AF_INET6 = 24,
        FREEBSD_AF_INET6 = 28,
        DARWIN_AF_INET6 = 30
    ]

    def self.decode_null endian, bytes
        Pcap.assert bytes.length >= 4, 'Truncated PCAP packet header: ' +
            "expected at least 4 bytes, got #{bytes.length} bytes"
        if endian == BIG_ENDIAN
            format = 'N'
        elsif endian == LITTLE_ENDIAN
            format = 'V'
        end
        family = bytes[0, 4].unpack(format)[0]
        bytes = bytes[4..-1]
        ethernet = Ethernet.new
        ethernet.src = '00:01:01:00:00:01'
        ethernet.dst = '00:01:01:00:00:02'
        ethernet.payload = ethernet.payload_raw = bytes
        if family != Socket::AF_INET and family != Socket::AF_INET6 and
                not BSD_AF_INET6.include?(family)
            raise ParseError, "Unknown PCAP packet header family: #{family}"
        end
        begin
            case family
            when Socket::AF_INET
                ethernet.type = Ethernet::ETHERTYPE_IP
                ethernet.payload = IPv4.from_bytes ethernet.payload
            when Socket::AF_INET6, FREEBSD_AF_INET6, OPENBSD_AF_INET6, DARWIN_AF_INET6
                ethernet.type = Ethernet::ETHERTYPE_IP6
                ethernet.payload = IPv6.from_bytes ethernet.payload
            else
                raise NotImplementedError
            end
        rescue ParseError => e
            Pcap.warning e
        end
        return ethernet
    end

    def self.decode_en10mb bytes
        return Ethernet.from_bytes(bytes)
    end

    def self.decode_linux_sll bytes
        Pcap.assert bytes.length >= 16, 'Truncated PCAP packet header: ' +
            "expected at least 16 bytes, got #{bytes.length} bytes"
        packet_type, link_type, addr_len = bytes.unpack('nnn')
        type = bytes[14, 2].unpack('n')[0]
        bytes = bytes[16..-1]
        ethernet = Ethernet.new
        ethernet.type = type
        ethernet.src = '00:01:01:00:00:01'
        ethernet.dst = '00:01:01:00:00:02'
        ethernet.payload = ethernet.payload_raw = bytes 
        begin
            case type
            when Ethernet::ETHERTYPE_IP
                ethernet.payload = IPv4.from_bytes ethernet.payload
            when Ethernet::ETHERTYPE_IP6
                ethernet.payload = IPv6.from_bytes ethernet.payload
            end
        rescue ParseError => e
            Pcap.warning e
        end
        return ethernet
    end

    def == other
        return self.class == other.class &&
            self.endian   == other.endian &&
            self.ts_sec   == other.ts_sec &&
            self.ts_usec  == other.ts_usec &&
            self.caplen   == other.caplen &&
            self.len      == other.len &&
            self.pkt      == other.pkt
    end
end

end
end
