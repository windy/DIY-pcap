
require 'diy/task'
require 'optparse'

pcap_port = "7878"
rpcap_port = "7879"

if ! $_PORT
  puts "Must set $_PORT value before call me"
  exit 1
end

options = {
  :ip => "0.0.0.0:#{$_PORT}",
}

OptionParser.new do |opts|
  
  opts.on("-f file", "File will be parsed") do |v|
    options[:file] = v
  end
  
  opts.on("-i ip", "--ip ip", "client or server : 0.0.0.0 or 0.0.0.0:#{$_PORT}", "default is 0.0.0.0:#{$_PORT}") do |v|
    options[:ip] = v
  end
  
  opts.on("-n device_name", "--name device_name", "Send or Recv device name") do |v|
    options[:device_name] = v
  end
  
  opts.on_tail("--show", "Show all devices name and exit") do 
    require 'diy/device_finder'
    DIY::DeviceFinder.pp_devices
    exit 0
  end
  
  opts.on_tail("--timer","Use TimerIdConv module instead of DRb's default idconv") do
    options[:timer] = true
  end
  
  opts.on_tail('-v','--version', 'Show version') do
    puts DIY::PCAP::VERSION
    exit 0
  end
  
  opts.on_tail('-V', 'detail mode') do
    DIY::Logger.level = ::Logger::DEBUG
    DIY::Logger.debug "Enable debug mode"
  end
  
  opts.on_tail('-h','--help', 'Show this help and exit') do
    puts opts
    exit 0
  end
end.parse!

if options[:file]
  require File.join( Dir.pwd, options[:file] )
else
  ip = options[:ip]
  if ip.include?(':')
    uri = "druby://#{ip}"
  else
    uri = "druby://#{ip}:#{$_PORT}"
  end
  
  if options[:device_name]
    device_name = options[:device_name]
  else
    require 'diy/device_finder'
    device_name = DIY::DeviceFinder.smart_select
  end
  device = DIY::Live.new(device_name)
  worker = DIY::Worker.new(device)
  worker_keeper = DIY::WorkerKeeper.new(worker, uri)
  if options[:timer]
    worker_keeper.use_timeridconv
  end
  worker_keeper.run
end