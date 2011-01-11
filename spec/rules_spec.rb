require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Yara::Rules do
  it "should be a class" do
    Yara::Rules.should be_kind_of(Class)
  end

  it "should initialize cleanly" do
    lambda { Yara::Rules.new }.should_not raise_error
  end

  context "Instances" do
    before(:each) do
      @rules = Yara::Rules.new
    end

    it "should indicate rules weight" do
      @rules.weight.should be_kind_of(Numeric)
      @rules.weight.should == 0
    end

    it "should have a compile_file method" do
      @rules.should be_respond_to(:compile_file)
    end

    it "should compile a file" do
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should_not raise_error
    end

    it "should raise an error when compiling an invalid filename" do
      lambda { @rules.compile_file("so totally bogus a file") }.should raise_error
    end

    it "should raise an error when compiling a file with bad syntax" do
      lambda { @rules.compile_file(__FILE__) }.should raise_error(Yara::Rules::CompileError)
    end

    it "should raise an error when duplicate file data is compiled" do
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should_not raise_error
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should raise_error(Yara::Rules::CompileError)
      @rules.weight.should > 0
    end

    it "should have a compile_string method" do
      @rules.should be_respond_to(:compile_string)
      lambda { @rules.compile_string("") }.should_not raise_error
      @rules.weight.should == 0
    end

    it "should compile a string" do
      rules = File.read(sample_file("upx.yara"))
      lambda { @rules.compile_string(rules) }.should_not raise_error
      @rules.weight.should > 0
    end

    it "should raise an error when compiling a string with bad syntax" do
      rules = File.read(sample_file("upx.yara")) << "some bogus stuff\n"
      lambda { @rules.compile_string(rules) }.should raise_error(Yara::Rules::CompileError)
      @rules.weight.should > 0 # it parsed everything up to the error
    end

    it "should raise an error when duplicate string data is compiled" do
      rules = File.read(sample_file("upx.yara"))
      lambda { @rules.compile_string(rules) }.should_not raise_error
      lambda { @rules.compile_string(rules) }.should raise_error(Yara::Rules::CompileError)
      @rules.weight.should > 0
    end

  end
end
