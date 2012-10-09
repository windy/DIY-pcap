# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class Header
    attr_accessor :magic, :version_major, :version_minor, :thiszone, :sigfigs,
        :snaplen, :linktype

    BIG_ENDIAN_FORMAT = 'nnNNNN'
    LITTLE_ENDIAN_FORMAT = 'vvVVVV'

    UNSUPPORTED_FORMATS =  { 
        0x474D4255 => "NetMon", # "GMBU"
        0x5452534E => "NA Sniffer (DOS)" # Starts with "TRSNIFF data"
    }

    def initialize
        @magic = BIG_ENDIAN
        @version_major = 2
        @version_minor = 4
        @thiszone = 0
        @sigfigs = 0
        @snaplen = 1500
        @linktype = DLT_NULL
    end

    def self.read ios
        header = Header.new
        bytes = ios.read 24
        Pcap.assert bytes, 'PCAP header missing'
        Pcap.assert bytes.length == 24, 'Truncated PCAP header: ' +
            "expected 24 bytes, got #{bytes.length} bytes"
        header.magic, _ = bytes[0, 4].unpack 'N'
        if header.magic == BIG_ENDIAN
            format = BIG_ENDIAN_FORMAT
        elsif header.magic == LITTLE_ENDIAN
            format = LITTLE_ENDIAN_FORMAT
        else 
            format = UNSUPPORTED_FORMATS[header.magic]
            if format.nil?
                err = "Unsupported packet capture format. "
            else
                err = "#{format} capture files are not supported. "
            end
            raise ParseError, err
        end
        header.version_major, header.version_minor, header.thiszone,
            header.sigfigs, header.snaplen, header.linktype = 
            bytes[4..-1].unpack format
        return header
    end

    def write io
        bytes = [BIG_ENDIAN, @version_major, @version_minor, @thiszone,
                 @sigfigs, @snaplen, DLT_EN10MB].pack('N' + BIG_ENDIAN_FORMAT)
        io.write bytes
    end

    def == other
        return self.class      == other.class &&
            self.magic         == other.magic &&
            self.version_major == other.version_major &&
            self.version_minor == other.version_minor &&
            self.thiszone      == other.thiszone &&
            self.sigfigs       == other.sigfigs &&
            self.snaplen       == other.snaplen &&
            self.linktype      == other.linktype
    end
end

end
end
