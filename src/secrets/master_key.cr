require "process"
require "./error"
require "./platform/keychain_macos"

module Secrets
  # The age master key — generated once at `init`, stored in Keychain
  # (synced across the user's Macs via iCloud Keychain), and read on
  # demand by the rest of the shard.
  #
  # Each Aloli operator has *their own* master key in their *own*
  # Keychain. `recipients.txt` lists the public keys of all members
  # of the team; vaults are encrypted to that list. v0.1 supports
  # only the operator's own key (single recipient).
  module MasterKey
    extend self

    KEYCHAIN_ACCOUNT = "master-key"

    record KeyPair, identity : String, recipient : String

    # Override the binary used for keygen (tests).
    def keygen_binary : String
      ENV["AGE_KEYGEN_BIN"]? || "age-keygen"
    end

    # Generate a new master key, store it in Keychain, return the
    # public key. Refuses if a key already exists in Keychain (use
    # `force: true` to overwrite — destructive).
    def generate!(force : Bool = false) : KeyPair
      KeychainMacOS.migrate_legacy_if_needed!(KEYCHAIN_ACCOUNT)
      if KeychainMacOS.exists?(KEYCHAIN_ACCOUNT) && !force
        raise Error.new("master key already exists in Keychain. Use force=true to overwrite (destructive).")
      end

      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run(keygen_binary, [] of String, output: stdout, error: stderr)
      raise Error.new("age-keygen failed: #{stderr.to_s.strip}") unless status.success?

      block = stdout.to_s
      identity = block.lines.find { |l| l.starts_with?("AGE-SECRET-KEY-1") }
      raise Error.new("age-keygen output did not contain a private key") unless identity
      identity = identity.strip

      pubkey_line = block.lines.find { |l| l.starts_with?("# public key:") }
      raise Error.new("age-keygen output did not contain a public key comment") unless pubkey_line
      recipient = pubkey_line.split(' ', 4).last.strip

      KeychainMacOS.store(KEYCHAIN_ACCOUNT, identity)
      KeyPair.new(identity, recipient)
    end

    # Read the master key from Keychain. Raises NotInitializedError if
    # no key is present (= `init` has not been run).
    def read : KeyPair
      KeychainMacOS.migrate_legacy_if_needed!(KEYCHAIN_ACCOUNT)
      raise NotInitializedError.new("no master key in Keychain — run `secrets init` first") unless KeychainMacOS.exists?(KEYCHAIN_ACCOUNT)
      identity = KeychainMacOS.fetch(KEYCHAIN_ACCOUNT)
      recipient = derive_recipient(identity)
      KeyPair.new(identity, recipient)
    end

    # Replace the Keychain entry with a fresh value (used by `import`).
    def install!(identity : String) : KeyPair
      raise Error.new("not a valid age private key") unless identity.starts_with?("AGE-SECRET-KEY-1")
      KeychainMacOS.store(KEYCHAIN_ACCOUNT, identity)
      KeyPair.new(identity, derive_recipient(identity))
    end

    # `age-keygen -y` reads an identity on stdin and prints the
    # corresponding recipient on stdout. Used to recover the public
    # key when we only have the private one (e.g. after `import`).
    private def self.derive_recipient(identity : String) : String
      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run(keygen_binary, ["-y"],
        input: IO::Memory.new(identity),
        output: stdout,
        error: stderr)
      raise Error.new("age-keygen -y failed: #{stderr.to_s.strip}") unless status.success?
      stdout.to_s.lines.find { |l| l.starts_with?("age1") }.try(&.strip) ||
        raise Error.new("age-keygen -y did not produce a public key")
    end
  end
end
