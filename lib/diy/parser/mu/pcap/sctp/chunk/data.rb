# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap
class SCTP
class Chunk

class Data < Chunk
    FLAG_LAST_SEG  = 0x01
    FLAG_FIRST_SEG = 0x02
    FLAG_UNORDERED = 0x04
    
    attr_accessor :tsn, :sid, :ssn, :ppid
    
    def initialize
        super
        
        @type = CHUNK_DATA
        @tsn  = 0
        @sid  = 0
        @ssn  = 0
        @ppid = 0
    end
    
    def self.from_bytes flags, size, bytes
        # Basic validation
        Pcap.assert(bytes.length >= 12,
                    "Truncated data chunk header: 12 > #{bytes.length}")
        
        # Read init chunk header
        tsn, sid, ssn, ppid = bytes.unpack('NnnN')
        
        # Create data chunk
        data       = Data.new
        data.flags = flags
        data.size  = size
        data.tsn   = tsn
        data.sid   = sid
        data.ssn   = ssn
        data.ppid  = ppid
        
        # Save the payload
        data.payload_raw = data.payload = bytes[12..size - 5]
        
        # Return the result
        return data
    end
    
    def write io, ip
        chunk_header = [@type, @flags, @size].pack('CCn')
        data_header  = [@tsn, @sid, @ssn, @ppid].pack('NnnN')
        
        # Write Chunk header followed by the Data chunk header and payload
        io.write(chunk_header)
        io.write(data_header)
        io.write(@payload_raw)
        
        # Write padding, if necessary
        if size < padded_size
            (padded_size - size).times do
                io.write("\x00")
            end
        end
    end
    
    def ordered?
        if 0 == @flags[2]
            return true
        else
            return false
        end
    end
    
    def first_segment?
        if 1 == @flags[1] and 0 == @flags[0]
            return true
        else
            return false
        end
    end
    
    def last_segment?
        if 0 == @flags[1] and 1 == @flags[0]
            return true
        else
            return false
        end
    end
    
    def complete_segment?
        if 1 == @flags[1] and 1 == @flags[0]
            return true
        else
            return false
        end
    end
    
    def to_s
        flags_s = '['
        
        if ordered?
            flags_s += 'ordered, '
        else
            flags_s += 'unordered, '
        end
        
        if complete_segment?
            flags_s += 'complete segment'
        elsif first_segment?
            flags_s += 'first segment'
        elsif last_segment?
            flags_s += 'last segment'
        else
            flags_s += 'middle segment'
        end
        
        flags_s += ']'
        
        return "data(%s, %d, %d, %d, %d, %d, %s)" % [flags_s,
                                                     @size,
                                                     @tsn,
                                                     @sid,
                                                     @ssn,
                                                     @ppid,
                                                     @payload.inspect]
    end
end # class Data

end # class Chunk
end # class SCTP
end # class Pcap
end # module Mu
