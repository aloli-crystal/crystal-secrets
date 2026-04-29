require "./spec_helper"

describe Secrets::Recovery do
  describe "round-trip export/import" do
    it "round-trips an age identity through a passphrase paper" do
      stdout = IO::Memory.new
      Process.run("age-keygen", [] of String, output: stdout)
      identity = stdout.to_s.lines.find! { |l| l.starts_with?("AGE-SECRET-KEY-1") }.strip
      pass = "perplex grouchy abdomen catacomb mournful prancing slingshot"

      paper = Secrets::Recovery.export(identity, pass)
      paper.starts_with?("-----BEGIN CRYSTAL-SECRETS RECOVERY-----").should be_true

      restored = Secrets::Recovery.import(paper, pass)
      restored.should eq(identity)
    end

    it "rejects an identity that is not an age private key" do
      expect_raises(Secrets::RecoveryError, /AGE-SECRET-KEY-1/) do
        Secrets::Recovery.export("not-a-key", "passphrase")
      end
    end

    it "rejects an empty passphrase" do
      expect_raises(Secrets::RecoveryError, /passphrase/) do
        Secrets::Recovery.export("AGE-SECRET-KEY-1ABC", "")
      end
    end

    it "fails on import when the passphrase is wrong" do
      stdout = IO::Memory.new
      Process.run("age-keygen", [] of String, output: stdout)
      identity = stdout.to_s.lines.find! { |l| l.starts_with?("AGE-SECRET-KEY-1") }.strip
      paper = Secrets::Recovery.export(identity, "good")

      expect_raises(Secrets::VaultError) do
        Secrets::Recovery.import(paper, "wrong")
      end
    end

    it "fails on import when the decrypted content is not an age key" do
      # Build a paper that decrypts to garbage rather than an age key
      garbage = Secrets::Vault.encrypt_with_passphrase("not an age key", "x")
      expect_raises(Secrets::RecoveryError, /not an age private key/) do
        Secrets::Recovery.import(garbage, "x")
      end
    end
  end
end
