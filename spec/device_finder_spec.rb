require 'spec_helper'
require 'diy/device_finder'

describe DIY::DeviceFinder do
  it "#devices" do
    DIY::DeviceFinder.devices
  end
  
  it "#pp_devices" do
    DIY::DeviceFinder.pp_devices
  end
  
  it "#smart_select" do
    DIY::DeviceFinder.smart_select.should be_kind_of(String)
  end
end