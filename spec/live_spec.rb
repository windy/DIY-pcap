require 'spec_helper'
require 'diy/device_finder'

describe DIY::Live do
  it "#net" do
    live = DIY::Live.new( DIY::DeviceFinder.smart_select )
    puts live.net
  end
end