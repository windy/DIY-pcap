require 'spec_helper'

describe DIY::Utils do
  it "#pp" do
    DIY::Utils.pp('a' * 100).should == ('a' * 11 + '...').dump + "(100 sizes)"
  end
  
  it "#src_mac" do
    DIY::Utils.src_mac( 'a' * 100 ).should == "a" * 6
  end

  it "#dst_mac" do
    DIY::Utils.dst_mac( 'a' * 100 ).should == "a" * 6
  end

end