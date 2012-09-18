module DIY
  class DeviceFinder
    class <<self
      def smart_select
        ret = devices.find do |device, net|
          !device.match(/dialup/) && net != nil
        end
        if ret
          ret[0]
        else
          devices[0]
        end
      end
      
      def pp_devices
        devices.each do |device, net|
          printf "%20s\t:\t%s\n", device, net
        end
      end
      
      def devices
        FFI::PCap.dump_devices
      end
    end
  end
end