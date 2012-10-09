# http://www.mudynamics.com
# http://labs.mudynamics.com
# http://www.pcapr.net

module Mu
class Pcap
class SCTP
class Parameter

class IpAddress < Parameter
    attr_accessor :value
    
    def initialize
        super
        
        @value = nil
    end
    
    def self.from_bytes type, size, bytes
        # Basic validation
        if PARAM_IPV4 == type
            Pcap.assert(size == 8, "Invalid IPv4 address: 4 != #{size}")
        else
            Pcap.assert(size == 20, "Invalid IPv6 address: 16 != #{size}")
        end
        
        # Create IP address parameter
        ip_address       = IpAddress.new
        ip_address.type  = type
        ip_address.size  = size
        ip_address.value = IPAddr.new_ntoh(bytes[0, size - 4])
        
        # Set raw payload
        ip_address.payload_raw = bytes[0, size - 4]
        
        # Return the result
        return ip_address
    end
    
    def to_s
        return "address(%s)" % [@value]
    end
end # class IpAddress

end # class Parameter
end # class SCTP
end # class Pcap
end # module Mu
