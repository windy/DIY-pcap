require 'spec_helper'
describe DIY::MacLearner do
  
  before(:each) do
    @ml = DIY::MacLearner.new
  end
  
  def make_packet(src, dst)
    src = src * 6
    dst = dst * 6
    dst + src
  end
  
  it "#tellme new packet" do
    pkt = make_packet( "\2", "\4")
    @ml.tellme(pkt).should == :A
  end
  
  it "#tellme again packet" do
    pkt = make_packet( "\2", "\4" )
    @ml.tellme(pkt)
    @ml.tellme(pkt).should == :A
    #~ @ml.instance_variable_get("@table").size.should == 1
    b_pkt = make_packet( "\4" , "\2" )
    @ml.tellme(b_pkt).should == :B
    #~ @ml.instance_variable_get("@table").size.should == 2
    # 另一个新包
    c_pkt = make_packet( "\6", "\8" )
    @ml.tellme(c_pkt).should == :A
    #~ @ml.instance_variable_get("@table").size.should == 3
    #~ pp @ml.instance_variable_get("@table")
    # 目标地址选定的
    d_pkt = make_packet( "\8", "\2")
    @ml.tellme(d_pkt).should == :B
    #~ pp @ml.instance_variable_get("@table") 
    @ml.instance_variable_get("@table")["\8"*6][0].should == :B
    dd_pkt = make_packet( "\8", "\10")
    @ml.tellme(dd_pkt).should == :B
    # 有冲突的
    e_pkt = make_packet( "\2", "\6" )
    lambda { @ml.tellme(e_pkt) }.should raise_error(DIY::MacLearnConflictError)
    # 解决冲突
    #~ @ml.instance_variable_get("@table")[ "\6"*6 ][1] = Time.now - 10*60
    #~ @ml.tellme(e_pkt).should == :A
    #~ @ml.tellme(e_pkt).should == :A
    
    # 源目的相同的
    ee_pkt = make_packet( "\2", "\2")
    lambda { @ml.tellme(ee_pkt) }.should raise_error(DIY::MacLearnConflictError)
  end
  
  it "#tellme group and broad" do
    @ml.tellme( make_packet("\2", "\377") ).should == :A
    @ml.tellme( make_packet( "\377", "\2") ).should == :B
    @ml.instance_variable_get("@table").size.should == 1
    @ml.tellme( make_packet("\377", "\4") ).should == :A
    
    @ml.tellme( make_packet("\1", "\4")).should == :A
    @ml.tellme( make_packet("\6", "\1")).should == :A
    @ml.tellme( make_packet("\4", "\1")).should == :B
  end
end