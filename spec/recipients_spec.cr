require "./spec_helper"
require "file_utils"

# Tests for the recipients roster. We can't easily redirect
# RECIPIENTS_FILE at runtime (it's resolved at compile time from
# `Secrets::CONFIG_DIR`), so we save/restore the real file around
# each test that needs to mutate it.
private def with_clean_recipients(&)
  path = Secrets::Recipients::RECIPIENTS_FILE
  backup = File.exists?(path) ? File.read(path) : nil
  File.delete(path) if File.exists?(path)
  begin
    yield
  ensure
    if backup
      File.write(path, backup)
    elsif File.exists?(path)
      File.delete(path)
    end
  end
end

describe Secrets::Recipients do
  describe ".list_named" do
    it "returns an empty hash when recipients.toml is absent" do
      with_clean_recipients do
        Secrets::Recipients.list_named.should be_empty
      end
    end
  end

  describe ".add" do
    it "creates the file and stores name => key" do
      with_clean_recipients do
        Secrets::Recipients.add("alice", "age1aliceXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.list_named["alice"]?.should eq("age1aliceXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
      end
    end

    it "rejects keys that don't start with age1" do
      with_clean_recipients do
        expect_raises(Secrets::Error, /must start with 'age1'/) do
          Secrets::Recipients.add("eve", "ssh-rsa AAAA...")
        end
      end
    end

    it "rejects names containing '.' (TOML key separator)" do
      with_clean_recipients do
        expect_raises(Secrets::Error, /must not contain '\.'/) do
          Secrets::Recipients.add("alice.bob", "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        end
      end
    end

    it "rejects empty names" do
      with_clean_recipients do
        expect_raises(Secrets::Error, /must not be empty/) do
          Secrets::Recipients.add("", "age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        end
      end
    end

    it "appends multiple recipients into the same file" do
      with_clean_recipients do
        Secrets::Recipients.add("alice", "age1aliceXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.add("bob", "age1bobXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        named = Secrets::Recipients.list_named
        named.size.should eq(2)
        named["alice"]?.should_not be_nil
        named["bob"]?.should_not be_nil
      end
    end

    it "updates the value when adding the same name twice" do
      with_clean_recipients do
        Secrets::Recipients.add("alice", "age1aliceFIRSTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.add("alice", "age1aliceSECONDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.list_named["alice"]?.should eq("age1aliceSECONDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
      end
    end
  end

  describe ".remove" do
    it "returns false when recipients.toml is absent" do
      with_clean_recipients do
        Secrets::Recipients.remove("ghost").should be_false
      end
    end

    it "returns false when the name is not in the roster" do
      with_clean_recipients do
        Secrets::Recipients.add("alice", "age1aliceXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.remove("bob").should be_false
        Secrets::Recipients.list_named["alice"]?.should_not be_nil
      end
    end

    it "removes the entry and returns true" do
      with_clean_recipients do
        Secrets::Recipients.add("alice", "age1aliceXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.add("bob", "age1bobXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        Secrets::Recipients.remove("alice").should be_true
        Secrets::Recipients.list_named.keys.should eq(["bob"])
      end
    end
  end
end
