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
    pkt = make_packet( "a", "b")
    @ml.tellme(pkt).should == :A
  end
  
  it "#tellme again packet" do
    pkt = make_packet( "a", "b" )
    @ml.tellme(pkt)
    @ml.tellme(pkt).should == :A
    @ml.instance_variable_get("@table").size.should == 1
    b_pkt = make_packet( "b" , "a" )
    @ml.tellme(b_pkt).should == :B
    @ml.instance_variable_get("@table").size.should == 2
    # 另一个新包
    c_pkt = make_packet( "c", "d" )
    @ml.tellme(c_pkt).should == :A
    @ml.instance_variable_get("@table").size.should == 3
    #~ pp @ml.instance_variable_get("@table")
    # 目标地址选定的
    d_pkt = make_packet( "d", "a")
    @ml.tellme(d_pkt).should == :B
    #~ pp @ml.instance_variable_get("@table") 
    @ml.instance_variable_get("@table")["d"*6][0].should == :B
    dd_pkt = make_packet( "d", "k")
    @ml.tellme(dd_pkt).should == :B
    # 有冲突的
    e_pkt = make_packet( "a", "c" )
    lambda { @ml.tellme(e_pkt) }.should raise_error(DIY::MacLearnConflictError)
    # 解决冲突
    @ml.instance_variable_get("@table")[ "c"*6 ][1] = Time.now - 10*60
    @ml.tellme(e_pkt).should == :A
    
    # 源目的相同的
    ee_pkt = make_packet( "a", "a")
    @ml.tellme(ee_pkt).should == :A
    
  end
end