# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap
class SCTP
class Chunk

class InitAck < Init
    def initialize
        super
        
        @type = CHUNK_INIT_ACK
    end
    
    def self.from_bytes flags, size, bytes
        # Basic validation
        Pcap.assert(bytes.length >= 16,
                    "Truncated init_ack chunk header: 16 > #{bytes.length}")
        
        # Read init_ack chunk header
        init_tag, a_rwnd, o_streams, i_streams, init_tsn = bytes.unpack('NNnnN')
        
        # Create init chunk
        init_ack           = InitAck.new
        init_ack.flags     = flags
        init_ack.size      = size
        init_ack.init_tag  = init_tag
        init_ack.a_rwnd    = a_rwnd
        init_ack.o_streams = o_streams
        init_ack.i_streams = i_streams
        init_ack.init_tsn  = init_tsn
        
        # Initialize the counter
        length = 16
        
        # Collect the chunks
        while length < bytes.length
            # Parse new parameter from the bytes
            parameter = Parameter.from_bytes(bytes[length..-1])
            
            # Get parameter size with padding
            length += parameter.padded_size
            
            # Add chunk to the list
            init_ack << parameter
        end
        
        # Return the result
        return init_ack
    end

    def to_s
        return "init_ack(%d, %d, %d, %d, %d, %d, %s)" % [@size,
                                                         @init_tag,
                                                         @a_rwnd,
                                                         @o_streams,
                                                         @i_streams,
                                                         @init_tsn,
                                                         @payload.join(", ")]
    end
end # class InitAck

end # class Chunk
end # class SCTP
end # class Pcap
end # module Mu
