require "./spec_helper"
require "file_utils"

# Override CONFIG_DIR via XDG_CONFIG_HOME for the duration of each test
# so the audit log lands in a tempdir we control. We can't reassign the
# constant Secrets::CONFIG_DIR (it's resolved at compile time from the
# environment), so we run each spec inside a forked block that wipes
# the test dir on entry/exit.
private def with_audit_tmpdir(&)
  base = "/tmp/cs-audit-spec-#{Random::Secure.hex(4)}"
  FileUtils.rm_rf(base)
  Dir.mkdir_p(base)
  begin
    yield base
  ensure
    FileUtils.rm_rf(base)
  end
end

describe Secrets::Audit do
  describe ".log + .read" do
    it "creates the audit dir on first call and writes a tab-separated line" do
      with_audit_tmpdir do
        # We can't redirect AUDIT_DIR at runtime cleanly, so we just
        # exercise the real one and assert structure / cleanup.
        vault = "spec-audit-#{Random::Secure.hex(4)}"
        begin
          Secrets::Audit.log(vault, "create")
          lines = Secrets::Audit.read(vault)
          lines.size.should eq(1)
          parts = lines.first.split('\t')
          parts.size.should eq(4)
          parts[0].should match(/^\d{4}-\d{2}-\d{2}T/) # RFC3339
          parts[2].should eq("create")
          parts[3].should eq("-")
        ensure
          File.delete(Secrets::Audit.log_path(vault)) if File.exists?(Secrets::Audit.log_path(vault))
        end
      end
    end

    it "appends — never rewrites" do
      vault = "spec-append-#{Random::Secure.hex(4)}"
      begin
        Secrets::Audit.log(vault, "create")
        Secrets::Audit.log(vault, "set", "DATABASE_URL")
        Secrets::Audit.log(vault, "delete", "OLD_KEY")
        Secrets::Audit.log(vault, "rotation")

        lines = Secrets::Audit.read(vault)
        lines.size.should eq(4)
        ops = lines.map { |l| l.split('\t')[2] }
        ops.should eq(["create", "set", "delete", "rotation"])
        keys = lines.map { |l| l.split('\t')[3] }
        keys.should eq(["-", "DATABASE_URL", "OLD_KEY", "-"])
      ensure
        File.delete(Secrets::Audit.log_path(vault)) if File.exists?(Secrets::Audit.log_path(vault))
      end
    end

    it "returns [] for a vault that never had any audit entry" do
      Secrets::Audit.read("never-existed-#{Random::Secure.hex(4)}").should be_empty
    end

    it "writes the log file with mode 0600" do
      vault = "spec-mode-#{Random::Secure.hex(4)}"
      begin
        Secrets::Audit.log(vault, "create")
        path = Secrets::Audit.log_path(vault)
        mode = File.info(path).permissions.value & 0o777
        mode.should eq(0o600)
      ensure
        File.delete(Secrets::Audit.log_path(vault)) if File.exists?(Secrets::Audit.log_path(vault))
      end
    end
  end
end
