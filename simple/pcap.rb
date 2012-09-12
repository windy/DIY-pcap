$LOAD_PATH.unshift File.join( File.dirname(__FILE__), '..', 'lib')
require 'rubygems'
require 'diy-pcap'
require 'diy/dig'

ss = DIY::SimpleStrategy.new

a = DIY::Builder.new do 
  use ss
  pcapfile Dir["pcaps/*.pcap"]
end

a.run