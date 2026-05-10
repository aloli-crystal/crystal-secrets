require "./spec_helper"

private def fresh_keypair : {String, String}
  stdout = IO::Memory.new
  Process.run("age-keygen", [] of String, output: stdout)
  kb = stdout.to_s
  identity = kb.lines.find! { |l| l.starts_with?("AGE-SECRET-KEY-1") }.strip
  recipient = kb.lines.find! { |l| l.starts_with?("# public key:") }.split(' ', 4).last.strip
  {identity, recipient}
end

describe Secrets::Vault do
  describe "round-trip with a generated age keypair" do
    # We use the real `age` binary (assumed installed via `brew
    # install age` on macOS). The test generates a fresh key via
    # `age-keygen` and exercises encrypt/decrypt round-trip.
    it "encrypts then decrypts a payload" do
      stdout = IO::Memory.new
      Process.run("age-keygen", [] of String, output: stdout)
      key_block = stdout.to_s
      identity = key_block.lines.find! { |l| l.starts_with?("AGE-SECRET-KEY-1") }.strip
      recipient = key_block.lines.find! { |l| l.starts_with?("# public key:") }.split(' ', 4).last.strip

      payload = "DATABASE_URL = \"postgres://...\"\nAPI_KEY = \"abc\"\n"
      ct = Secrets::Vault.encrypt(payload, recipient)
      ct.starts_with?("-----BEGIN AGE ENCRYPTED FILE-----").should be_true
      pt = Secrets::Vault.decrypt(ct, identity)
      pt.should eq(payload)
    end

    it "rejects a recipient that is not a public age key" do
      expect_raises(Secrets::VaultError, /age1/) do
        Secrets::Vault.encrypt("x", "not-an-age-key")
      end
    end

    it "rejects an identity that is not a private age key" do
      expect_raises(Secrets::VaultError, /AGE-SECRET-KEY-1/) do
        Secrets::Vault.decrypt("ciphertext", "not-an-age-secret-key")
      end
    end

    it "fails cleanly when the identity does not match the recipient" do
      stdout = IO::Memory.new
      Process.run("age-keygen", [] of String, output: stdout)
      kb1 = stdout.to_s
      identity1 = kb1.lines.find! { |l| l.starts_with?("AGE-SECRET-KEY-1") }.strip
      stdout2 = IO::Memory.new
      Process.run("age-keygen", [] of String, output: stdout2)
      kb2 = stdout2.to_s
      recipient2 = kb2.lines.find! { |l| l.starts_with?("# public key:") }.split(' ', 4).last.strip

      ct = Secrets::Vault.encrypt("x", recipient2)
      expect_raises(Secrets::VaultError, /decrypt failed/) do
        Secrets::Vault.decrypt(ct, identity1)
      end
    end
  end

  describe "multi-recipient encryption" do
    it "any of the recipient identities can decrypt the payload" do
      id1, rcp1 = fresh_keypair
      id2, rcp2 = fresh_keypair
      id3, rcp3 = fresh_keypair

      payload = "TEAM_SECRET = \"shared\"\n"
      ct = Secrets::Vault.encrypt(payload, [rcp1, rcp2, rcp3])

      Secrets::Vault.decrypt(ct, id1).should eq(payload)
      Secrets::Vault.decrypt(ct, id2).should eq(payload)
      Secrets::Vault.decrypt(ct, id3).should eq(payload)
    end

    it "rejects an empty recipient list" do
      expect_raises(Secrets::VaultError, /must not be empty/) do
        Secrets::Vault.encrypt("x", [] of String)
      end
    end

    it "rejects a malformed recipient inside the list" do
      _, rcp = fresh_keypair
      expect_raises(Secrets::VaultError, /age1/) do
        Secrets::Vault.encrypt("x", [rcp, "not-a-key"])
      end
    end

    it "single-recipient overload still works (backward compat)" do
      id, rcp = fresh_keypair
      ct = Secrets::Vault.encrypt("hello", rcp)
      Secrets::Vault.decrypt(ct, id).should eq("hello")
    end
  end

  describe "passphrase round-trip (recovery export/import)" do
    it "encrypts then decrypts with the same passphrase" do
      payload = "AGE-SECRET-KEY-1ABC123MASTER..."
      pass = "perplex grouchy abdomen catacomb mournful prancing slingshot"

      paper = Secrets::Vault.encrypt_with_passphrase(payload, pass)
      paper.starts_with?("-----BEGIN CRYSTAL-SECRETS RECOVERY-----").should be_true

      restored = Secrets::Vault.decrypt_with_passphrase(paper, pass)
      restored.should eq(payload)
    end

    it "fails with the wrong passphrase" do
      payload = "secret-key-blob"
      paper = Secrets::Vault.encrypt_with_passphrase(payload, "good passphrase")

      expect_raises(Secrets::VaultError) do
        Secrets::Vault.decrypt_with_passphrase(paper, "wrong passphrase")
      end
    end
  end
end
