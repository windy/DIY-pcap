# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

require 'tempfile'
require 'fileutils'
require 'mu/scenario/pcap/fields'
require 'mu/pcap'
require 'json'

module Mu
class Scenario

module Pcap
    TSHARK_READ_TIMEOUT     = 10.0 # seconds
    TSHARK_LINES_PER_PACKET = 16384
    TSHARK_OPTS = "-n -o tcp.desegment_tcp_streams:false"
    TSHARK_OPTS_SUFFIX = TSHARK_OPTS
    TSHARK_SIZE_OPTS = "-n -o 'column.format: cum_size, \"%B\"'"
    TSHARK_PSML_OPTS = %Q{#{TSHARK_OPTS} -o 'column.format: "Protocol", "%p", "Info", "%i"'}

    MAX_PCAP_SIZE = 102400 # 100KB
    MAX_RAW_PCAP_SIZE_MB = 25
    MAX_RAW_PCAP_SIZE = MAX_RAW_PCAP_SIZE_MB * 1024 * 1000
    EXCLUDE_FROM_SIZE_CHECK = ['rtp'].freeze

    class PcapTooLarge < StandardError; end
    
    def self.reset_options options
        return unless options
        tshark_opts = options << ' ' << TSHARK_OPTS_SUFFIX
        remove_const(:TSHARK_OPTS) if const_defined?(:TSHARK_OPTS)
        const_set(:TSHARK_OPTS, tshark_opts)
    end

    def self.validate_pcap_size(path)
        tshark_filter = EXCLUDE_FROM_SIZE_CHECK.map{ |proto| "not #{proto}" }.join " and "
        io = ::IO.popen "tshark #{TSHARK_SIZE_OPTS} -r #{path} -R '#{tshark_filter}' | tail -1"
        if ::IO.select [ io ], nil, nil, TSHARK_READ_TIMEOUT
            if io.eof?
                size = 0
            else
                last_line = io.readline
                size = last_line.to_i
            end
        end

        if size.nil? or size == 0
            size = File.size(path)
        end

        if size > MAX_PCAP_SIZE
            raise PcapTooLarge, "Selected packets have a size of #{size} bytes which " +
                "exceeds the #{MAX_PCAP_SIZE} byte maximum."
        end

        if size > MAX_RAW_PCAP_SIZE
            raise PcapTooLarge, "Selected packets have a raw size of #{size} bytes which " +
                "exceeds the #{MAX_RAW_PCAP_SIZE_MB}MB maximum."
        end

        return size
    end

    PAR_VERSION = 1
    def self.export_to_par pcap_path, opts=nil
        opts ||= {}

        # Open pcap file
        File.exist?(pcap_path) or raise "Cannot open file '#{pcap_path}'."
        validate_pcap_size pcap_path
        pcap = open pcap_path, 'rb'

        # Get Mu::Pcap::Packets
        packets = to_pcap_packets pcap, opts[:isolate_l7]

        # Write normalized packets to tempfile
        tmpdir = Dir.mktmpdir
        norm_pcap = File.open "#{tmpdir}/normalized.pcap", 'wb'
        pcap = Mu::Pcap.from_packets packets
        pcap.write norm_pcap
        norm_pcap.close

        # Get wireshark dissected field values for all packets.
        `tshark -T fields #{TSHARK_OPTS} #{Fields::TSHARK_OPTS} -Eseparator='\xff' -r #{norm_pcap.path} > #{tmpdir}/fields`
        fields = open "#{tmpdir}/fields", 'rb'

        # Get wireshark dissected field values for all packets.
        fields_array = []
        if fields
            packets.each do |packet|
                fields_array <<  Fields.next_from_io(fields)
            end
        end

        # Protocol specific preprocessing, packets may be deleted.
        Rtp.preprocess packets, fields_array

        File.open "#{tmpdir}/packets.dump", 'wb' do |f|
            Marshal.dump packets, f
        end

        # Create a second pcap with packets removed.
        norm_pcap = File.open "#{tmpdir}/normalized.pcap", 'wb'
        pcap = Mu::Pcap.from_packets packets
        pcap.write norm_pcap
        norm_pcap.close

        # Dump PSML to file.
        # (The no-op filter sometimes produces slighty more verbose descriptions.)
        `tshark -T psml #{TSHARK_PSML_OPTS} -r #{norm_pcap.path} -R 'rtp or not rtp' > #{tmpdir}/psml`

        # Dump PDML io file.
        `tshark -T pdml #{TSHARK_OPTS} -r #{norm_pcap.path} > #{tmpdir}/pdml`
        pdml = open "#{tmpdir}/pdml", 'rb'

        # Create about
        open "#{tmpdir}/about", 'w' do |about|
            about.puts({:par_version => PAR_VERSION}.to_json)
        end

        # Create zip
        Dir.chdir tmpdir do
            system "zip -q dissected.zip about pdml psml fields packets.dump normalized.pcap"
            return open("dissected.zip")
        end
    ensure
        if tmpdir
            FileUtils.rm_rf tmpdir
        end
    end

    def self.to_pcap_packets io, isolate_l7=true
        packets = []

        # Read Pcap packets from Pcap
        Mu::Pcap.each_pkthdr io do |pkthdr|
            if pkthdr.len != pkthdr.caplen
                raise Mu::Pcap::ParseError, "Error: Capture contains truncated packets. " +
                    "Try recapturing with an increased snapshot length."
            end
            if not pkthdr.pkt.is_a? Mu::Pcap::Ethernet
                warning 'Unable to parse packet, skipping.'
            end
            packets << pkthdr.pkt
        end

        if (packets.length == 0)
            raise Mu::Pcap::ParseError, "No valid packets found!"
        end

        packets = Mu::Pcap::IPv4.reassemble packets

        if isolate_l7
            packets = Mu::Pcap::Packet.isolate_l7 packets
        end

        packets = Mu::Pcap::Packet.normalize packets
        packets = Mu::Pcap::TCP.split packets

        packets
    end

    def self.warning msg
        $stderr.puts "WARNING: #{msg}"#, caller, $!
    end
end

end
end

require 'mu/scenario/pcap/rtp'
