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

    it "should compile a file" do
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should_not raise_error
      @rules.weight.should > 0
    end

    it "should compile an empty file" do
      lambda { @rules.compile_file("/dev/null") }.should_not raise_error
      @rules.weight.should == 0
    end


    it "should raise an error when compiling an invalid filename" do
      lambda { @rules.compile_file("so totally bogus a file") }.should raise_error
      @rules.weight.should == 0
    end

    it "should raise an error when compiling a file with bad syntax" do
      lambda { @rules.compile_file(__FILE__) }.should raise_error(Yara::Rules::CompileError)
      @rules.weight.should == 0
    end

    it "should raise an error when duplicate file data is compiled" do
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should_not raise_error
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should raise_error(Yara::Rules::CompileError)
      @rules.weight.should > 0
    end

    it "should compile a string" do
      rules = File.read(sample_file("upx.yara"))
      lambda { @rules.compile_string(rules) }.should_not raise_error
      @rules.weight.should > 0
    end

    it "should compile an empty string" do
      lambda { @rules.compile_string("") }.should_not raise_error
      @rules.weight.should == 0
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

    it "should indicate the current namespace" do
      @rules.current_namespace.should be_kind_of(String)
      @rules.current_namespace.should == "default"
    end

    it "should indicate all known namespaces" do
      @rules.namespaces.should be_kind_of(Array)
      @rules.namespaces.should == ["default"]
    end

    it "should support setting a new namespace" do
      @rules.namespaces.should be_kind_of(Array)
      @rules.namespaces.should == ["default"]

      @rules.set_namespace("a_new_namespace").should == "a_new_namespace"
      @rules.current_namespace.should == "a_new_namespace"
      @rules.namespaces.should be_kind_of(Array)
      @rules.namespaces.should == ["a_new_namespace", "default"]
    end

    it "should not create duplicate namespaces" do
      @rules.namespaces.should be_kind_of(Array)
      @rules.namespaces.should == ["default"]

      @rules.set_namespace("a_new_namespace").should == "a_new_namespace"
      @rules.current_namespace.should == "a_new_namespace"
      @rules.namespaces.should be_kind_of(Array)
      @rules.namespaces.should == ["a_new_namespace", "default"]

      @rules.set_namespace("default").should == "default"
      @rules.current_namespace.should == "default"
      @rules.namespaces.should == ["a_new_namespace", "default"]

      @rules.set_namespace("a_new_namespace").should == "a_new_namespace"
      @rules.current_namespace.should == "a_new_namespace"
      @rules.namespaces.should == ["a_new_namespace", "default"]
    end
  end
end
