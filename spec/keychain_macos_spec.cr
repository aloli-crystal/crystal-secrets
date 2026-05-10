require "./spec_helper"
require "file_utils"

# Tests for the Keychain backend, replacing /usr/bin/security with a
# fake shell script that records every invocation (args + stdin) into
# a log file the test then inspects. Lets us assert :
#  - the secret never appears in argv
#  - the right subcommand is invoked
#  - exit code drives KeychainError correctly

# Stateful fake: stores entries on disk under a per-service file so
# find/store/delete reflect actual state. Required to test migration
# sequences whose later results depend on earlier ones.
private def with_stateful_security(preset : Hash(String, String) = {} of String => String, &)
  base = "/tmp/cs-keychain-stateful"
  state = "#{base}/state"
  bin = "#{base}/security"
  FileUtils.rm_rf(base)
  Dir.mkdir_p(state)

  preset.each do |service_account, value|
    File.write(File.join(state, service_account), value)
  end

  script = <<-SH
  #!/bin/sh
  STATE="#{state}"
  mode=""
  service=""
  account=""
  while [ $# -gt 0 ]; do
    case "$1" in
      add-generic-password)    mode=add;    shift ;;
      find-generic-password)   mode=find;   shift ;;
      delete-generic-password) mode=delete; shift ;;
      -s) service="$2"; shift 2 ;;
      -a) account="$2"; shift 2 ;;
      *)  shift ;;
    esac
  done
  key="$STATE/${service}__${account}"
  case "$mode" in
    add)    cat > "$key"; exit 0 ;;
    find)   [ -f "$key" ] && cat "$key" && exit 0; exit 44 ;;
    delete) rm -f "$key"; exit 0 ;;
  esac
  exit 1
  SH
  File.write(bin, script)
  File.chmod(bin, 0o755)

  ENV["SECURITY_BIN"] = bin
  begin
    yield state
  ensure
    ENV.delete("SECURITY_BIN")
    FileUtils.rm_rf(base)
  end
end

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
        recorded.should contain("-s dev.aloli.secrets")
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

  describe ".migrate_legacy_if_needed!" do
    it "is a no-op when no entry exists anywhere" do
      with_stateful_security do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_false
        Dir.children(state).should be_empty
      end
    end

    it "is a no-op when only the new entry exists" do
      preset = {"dev.aloli.secrets__master-key" => "AGE-SECRET-KEY-1NEW"}
      with_stateful_security(preset: preset) do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_false
        File.exists?(File.join(state, "dev.aloli.secrets__master-key")).should be_true
        File.exists?(File.join(state, "dev.aloli.crystal-secrets__master-key")).should be_false
      end
    end

    it "copies a legacy-only entry to the new service and deletes the legacy one" do
      preset = {"dev.aloli.crystal-secrets__master-key" => "AGE-SECRET-KEY-1LEGACY"}
      with_stateful_security(preset: preset) do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_true
        File.read(File.join(state, "dev.aloli.secrets__master-key")).should eq("AGE-SECRET-KEY-1LEGACY")
        File.exists?(File.join(state, "dev.aloli.crystal-secrets__master-key")).should be_false
      end
    end

    it "leaves the new entry untouched if both exist (= legacy obsolete)" do
      preset = {
        "dev.aloli.crystal-secrets__master-key" => "AGE-SECRET-KEY-1OLD",
        "dev.aloli.secrets__master-key"         => "AGE-SECRET-KEY-1AUTHORITATIVE",
      }
      with_stateful_security(preset: preset) do |state|
        Secrets::KeychainMacOS.migrate_legacy_if_needed!("master-key").should be_false
        File.read(File.join(state, "dev.aloli.secrets__master-key"))
          .should eq("AGE-SECRET-KEY-1AUTHORITATIVE")
        # The legacy entry remains: not our job to clean it up if the
        # user explicitly created the new one in parallel.
        File.exists?(File.join(state, "dev.aloli.crystal-secrets__master-key")).should be_true
      end
    end
  end
end
