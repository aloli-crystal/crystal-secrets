require "./spec_helper"
require "file_utils"

# Tests for the Keychain backend, replacing /usr/bin/security with a
# fake shell script that records every invocation (args + stdin) into
# a log file the test then inspects. Lets us assert :
#  - the secret never appears in argv
#  - the right subcommand is invoked
#  - exit code drives KeychainError correctly

private def with_fake_security(behaviour : String? = nil, &)
  Dir.mkdir_p("/tmp/cs-keychain-test")
  log = "/tmp/cs-keychain-test/calls.log"
  bin = "/tmp/cs-keychain-test/security"
  File.delete(log) if File.exists?(log)

  script = String.build do |s|
    s << <<-SH
    #!/bin/sh
    LOG="#{log}"
    {
      printf 'CMD:'
      for a in "$@"; do printf ' %s' "$a"; done
      printf '\\n'
      stdin=$(cat)
      printf 'STDIN:%s\\n' "$stdin"
    } >> "$LOG"
    SH
    if behaviour
      s << "\n" << behaviour << "\n"
    else
      s << "\nexit 0\n"
    end
  end
  File.write(bin, script)
  File.chmod(bin, 0o755)

  ENV["SECURITY_BIN"] = bin
  begin
    yield log
  ensure
    ENV.delete("SECURITY_BIN")
    FileUtils.rm_rf("/tmp/cs-keychain-test")
  end
end

describe Secrets::KeychainMacOS do
  describe ".store" do
    it "calls add-generic-password with the right service/account and the value via stdin" do
      with_fake_security do |log|
        Secrets::KeychainMacOS.store("master-key", "AGE-SECRET-KEY-1...")
        recorded = File.read(log)
        recorded.should contain("add-generic-password")
        recorded.should contain("-a master-key")
        recorded.should contain("-s dev.aloli.crystal-secrets")
        recorded.should contain("-U")
        recorded.should contain("STDIN:AGE-SECRET-KEY-1...")
      end
    end

    it "never puts the secret on argv" do
      secret = "very-private-AGE-SECRET-KEY-1abc123"
      with_fake_security do |log|
        Secrets::KeychainMacOS.store("master-key", secret)
        cmd_line = File.read(log).lines.find! { |l| l.starts_with?("CMD:") }
        cmd_line.should_not contain(secret)
      end
    end

    it "raises KeychainError when security exits non-zero" do
      with_fake_security(behaviour: "exit 1") do
        expect_raises(Secrets::KeychainError, /failed/) do
          Secrets::KeychainMacOS.store("master-key", "x")
        end
      end
    end
  end

  describe ".fetch" do
    it "returns the value from stdout (chomped)" do
      with_fake_security(behaviour: "echo 'AGE-SECRET-KEY-1xyz'") do
        Secrets::KeychainMacOS.fetch("master-key").should eq("AGE-SECRET-KEY-1xyz")
      end
    end

    it "raises KeychainError when entry not found (exit 44)" do
      with_fake_security(behaviour: "exit 44") do
        expect_raises(Secrets::KeychainError, /not found/) do
          Secrets::KeychainMacOS.fetch("master-key")
        end
      end
    end
  end

  describe ".exists?" do
    it "returns true on success" do
      with_fake_security do
        Secrets::KeychainMacOS.exists?("master-key").should be_true
      end
    end

    it "returns false on failure" do
      with_fake_security(behaviour: "exit 44") do
        Secrets::KeychainMacOS.exists?("master-key").should be_false
      end
    end
  end

  describe ".delete" do
    it "calls delete-generic-password and ignores absent entries" do
      with_fake_security do |log|
        Secrets::KeychainMacOS.delete("master-key")
        File.read(log).should contain("delete-generic-password")
      end
    end
  end
end
