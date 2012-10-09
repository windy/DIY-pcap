# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap

class SCTP < Packet
    attr_accessor :src_port, :dst_port, :verify_tag, :checksum

    # SCTP chunk types
    CHUNK_DATA                        = 0x00
    CHUNK_INIT                        = 0x01
    CHUNK_INIT_ACK                    = 0x02
    CHUNK_SACK                        = 0x03
    CHUNK_HEARTBEAT                   = 0x04
    CHUNK_HEARTBEAT_ACK               = 0x05
    CHUNK_ABORT                       = 0x06
    CHUNK_SHUTDOWN                    = 0x07
    CHUNK_SHUTDOWN_ACK                = 0x08
    CHUNK_ERROR                       = 0x09
    CHUNK_COOKIE_ECHO                 = 0x0A
    CHUNK_COOKIE_ACK                  = 0x0B
    CHUNK_ECNE                        = 0x0C
    CHUNK_CWR                         = 0x0D
    CHUNK_SHUTDOWN_COMPLETE           = 0x0E
    CHUNK_AUTH                        = 0x0F
    CHUNK_ASCONF_ACK                  = 0x80
    CHUNK_PADDING                     = 0x84
    CHUNK_FORWARD_TSN                 = 0xC0
    CHUNK_ASCONF                      = 0xC1
    
    # SCTP parameter types
    PARAM_IPV4                        = 0x0005
    PARAM_IPV6                        = 0x0006
    PARAM_STATE_COOKIE                = 0x0007
    PARAM_COOKIE_PRESERVATIVE         = 0x0009
    PARAM_HOST_NAME_ADDR              = 0x000B
    PARAM_SUPPORTED_ADDR_TYPES        = 0x000C
    PARAM_ECN                         = 0x8000
    PARAM_RANDOM                      = 0x8002
    PARAM_CHUNK_LIST                  = 0x8003
    PARAM_HMAC_ALGORITHM              = 0x8004
    PARAM_PADDING                     = 0x8005
    PARAM_SUPPORTED_EXTENSIONS        = 0x8006
    PARAM_FORWARD_TSN                 = 0xC000
    PARAM_SET_PRIMARY_ADDR            = 0xC004
    PARAM_ADAPTATION_LAYER_INDICATION = 0xC006
    
    def initialize
        super
        
        @src_port   = 0
        @dst_port   = 0
        @verify_tag = 0
        @checksum   = 0
        @payload    = []
    end

    def flow_id
        return [:sctp, @src_port, @dst_port, @verify_tag]
    end

    def reverse_flow_id
        return [:sctp, @dst_port, @src_port, @checksum]
    end

    # Creates SCTP packet from the payload
    def self.from_bytes bytes
        # Basic packet validation
        Pcap.assert(bytes.length >= 12,
                    "Truncated SCTP header: 12 > #{bytes.length}")
        Pcap.assert(bytes.length >= 16,
                    "Truncated SCTP packet: got only #{bytes.length} bytes")
        
        # Read SCTP header
        sport, dport, vtag, cksum = bytes.unpack('nnNN')
        
        # Create SCTP packet and populate SCTP header fields
        sctp            = SCTP.new
        sctp.src_port   = sport
        sctp.dst_port   = dport
        sctp.verify_tag = vtag
        sctp.checksum   = cksum
        
        # Initialize the counter
        length = 12
        
        # Collect the chunks
        while length < bytes.length
            # Parse new chunk from the bytes
            chunk = Chunk.from_bytes(bytes[length..-1])
            
            # Get chunk size with padding
            length += chunk.padded_size
            
            # Add chunk to the list
            sctp << chunk
        end

        # Sync the payload
        sctp.sync_payload
        
        # Return the result
        return sctp
    end

    class ReorderError < StandardError ; end
    
    # Reorders SCTP packets, if necessary
    def self.reorder packets
        # Initialize
        tsns              = {}
        init_packets      = {}
        init_ack_packets  = {}
        reordered_packets = []
        
        # Iterate over each packet
        while not packets.empty?
            # Get next packet
            packet = packets.shift
            
            # Do not reorder non-SCTP packets
            if not sctp?(packet)
                reordered_packets << packet
            else
                # Get SCTP portion
                sctp = packet.payload.payload
                
                # Sanity checks and packet filtering/preprocessing
                if 0 == sctp.verify_tag and not sctp.init?
                    # Non-Init packet with 0 verify tag
                    raise ReorderError, "Non-Init packet with zero verify tag"
                elsif sctp.init_or_ack? and 1 < sctp.chunk_count
                    # Init/InitAck packet with more with one chunk
                    raise ReorderError, "Init/Ack packet with more than 1 chunk"
                elsif sctp.init?
                    # Use checksum to save reverse verify tag in the Init packet
                    sctp.checksum = sctp[0].init_tag

                    # Save orphaned Init packets until we find the Ack
                    init_packets[sctp.reverse_flow_id] = sctp
                    
                    # Add packet for further processing
                    reordered_packets << packet
                elsif sctp.init_ack?
                    # Lookup Init packet and construct it's flow it
                    init_packet = init_packets.delete(sctp.flow_id)

                    # Did we find anything?
                    if init_packet
                        # Set verify tag in the Init packet
                        init_packet.verify_tag = sctp[0].init_tag

                        # Set reverse verify tag in the InitAck packet
                        sctp.checksum = init_packet.verify_tag

                        # Re-insert INIT packet keyed by its flow id
                        init_packets[init_packet.flow_id] = init_packet
                    else
                        Pcap.warning("Orphaned SCTP INIT_ACK packet")
                    end

                    # Save InitAck packet
                    init_ack_packets[sctp.flow_id] = sctp
                    
                    # Add packet for further processing
                    reordered_packets << packet
                elsif sctp.has_data?
                    # SCTP packet with user data; lookup Init or InitAck packet
                    init_packet     = init_packets[sctp.flow_id]
                    init_ack_packet = init_ack_packets[sctp.flow_id]

                    # It should belong to either one flow id or the other
                    if init_packet
                        # Set reverse verify tag from Init packet
                        sctp.checksum = init_packet.checksum
                    elsif init_ack_packet
                        # Set reverse flow id from InitAck packet
                        sctp.checksum = init_ack_packet.checksum
                    else
                        # Orphaned SCTP packet -- not very good
                        Pcap.warning("Orphaned SCTP DATA packet detected")
                    end

                    # If we have just one chunk we are done
                    if 1 == sctp.chunk_count and not tsns.member?(sctp[0].tsn)
                        # Save TSN
                        tsns[sctp[0].tsn] = sctp[0]

                        # sync the payload
                        sctp.sync_payload

                        # Add packet for further processing
                        reordered_packets << packet
                    else
                        # Split each data chunk in a separate SCTP packet
                        sctp.chunk_count.times do
                            # Get next chunk
                            chunk = sctp.shift

                            # Is it data?
                            if CHUNK_DATA == chunk.type
                                # Yes, check for duplicate TSNs
                                if not tsns.member?(chunk.tsn)
                                    # Not a duplicate; create new SCTP packet
                                    packet_new = packet.deepdup

                                    # Create new SCTP payload
                                    sctp_new = SCTP.new
                                    sctp_new.src_port   = sctp.src_port
                                    sctp_new.dst_port   = sctp.dst_port
                                    sctp_new.verify_tag = sctp.verify_tag
                                    sctp_new.checksum   = sctp.checksum

                                    # Add the chunk
                                    sctp_new << chunk

                                    # Add SCTP payload to the new packet
                                    packet_new.payload.payload = sctp_new

                                    # Save TSN
                                    tsns[chunk.tsn] = chunk

                                    # Sync the payload
                                    sctp_new.sync_payload

                                    # Add packet for further processing
                                    reordered_packets << packet_new
                                else
                                    Pcap.warning("Duplicate chunk: #{chunk.tsn}")
                                end
                            else
                                Pcap.warning("Non-data chunk: #{chunk.type}")
                            end
                        end
                    end
                else
                    # Other SCTP packet; we are not interested at this time
                end
            end
        end
        
        # Return the result
        return reordered_packets
    end
    
    def write io, ip
        # Give a warning if packet size exceeds maximum allowed
        if @payload_raw and @payload_raw.length + 20 > 65535
            Pcap.warning("SCTP payload is too large")
        end
        
        # Calculate CRC32 checksum on the packet; temporarily removed due to a
        # hack that uses checksum to link forward and reverse SCTP flow IDs.
        #header = [@src_port, @dst_port, @verify_tag, 0].pack('nnNN')
        #checksum = SCTP.crc32(header + @payload_raw)
        header = [@src_port, @dst_port, @verify_tag, @checksum].pack('nnNN')
        
        # Write SCTP header followed by each chunk
        io.write(header)
        
        # Write each chunks' data
        @payload.each do |chunk|
            chunk.write(io, ip)
        end
    end

    def sync_payload
        # Reset raw bytes
        @payload_raw = ''
        
        # Iterate over each chunk
        @payload.each do |chunk|
            @payload_raw << chunk.payload_raw
        end
        
        # Reset raw payload if it's empty
        @payload_raw = nil if @payload_raw == ''
    end
    
    def self.crc32 bytes
        r = 0xFFFFFFFF
        
        bytes.each_byte do |b|
            r ^= b
            
            8.times do
              r = (r >> 1) ^ (0xEDB88320 * (r & 1))
            end
        end
        
        return r ^ 0xFFFFFFFF
    end
    
    def self.sctp? packet
        return packet.is_a?(Ethernet) &&
               packet.payload.is_a?(IP) &&
               packet.payload.payload.is_a?(SCTP)
    end
    
    def << chunk
        @payload << chunk
    end
    
    def shift
        return @payload.shift
    end
    
    def [] index
        return @payload[index]
    end
    
    def chunk_count
        return @payload.size
    end
    
    def has_data?
        return @payload.any? do |chunk|
            CHUNK_DATA == chunk.type
        end
    end

    def to_s
        return "sctp(%d, %d, %d, %s)" % [@src_port,
                                         @dst_port,
                                         @verify_tag,
                                         @payload.join(", ")]
    end

    def == other
        return super                               &&
               self.src_port == other.src_port     &&
               self.dst_port == other.dst_port     &&
               self.verify_tag == other.verify_tag &&
               self.payload.size == other.payload.size
    end
    
    def init?
        if CHUNK_INIT == @payload[0].type
            return true
        else
            return false
        end
    end

    def init_ack?
        if CHUNK_INIT_ACK == @payload[0].type
            return true
        else
            return false
        end
    end

    def init_or_ack?
        if CHUNK_INIT == @payload[0].type or CHUNK_INIT_ACK == @payload[0].type
            return true
        else
            return false
        end
    end
end # class SCTP

end # class Pcap
end # module Mu

require 'mu/pcap/sctp/chunk'
