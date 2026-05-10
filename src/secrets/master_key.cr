require "process"
require "./error"
require "./platform/keychain_macos"

module Secrets
  # The age master key — generated once at `init`, stored in
  # Keychain on macOS (synced across the user's Macs via iCloud
  # Keychain) or in a mode-0600 identity file on other platforms,
  # and read on demand by the rest of the shard.
  #
  # Each Aloli operator has *their own* master key in their *own*
  # Keychain (or own home directory). `recipients.toml` lists the
  # public keys of all members of the team; vaults are encrypted
  # to that list (cf. v0.4.0 multi-recipients).
  #
  # ## Storage layout, per platform
  #
  # macOS  → Keychain entry under (service: dev.aloli.secrets,
  #          account: master-key). The identity file at
  #          ~/.config/secrets/identity is also tolerated as a
  #          fallback if Keychain has no entry — useful when SSH'ing
  #          into a Mac without GUI session.
  #
  # Linux,
  # FreeBSD, → Identity file at `${XDG_CONFIG_HOME:-~/.config}/
  # other      secrets/identity`, mode 0600. v0.5.0 ships this minimal
  #            backend so a server can decrypt vaults without macOS.
  #            Linux Secret Service / FreeBSD passphrase / Windows
  #            Credential Manager are out of scope for v0.5 — the
  #            file backend is the contract.
  module MasterKey
    extend self

    KEYCHAIN_ACCOUNT = "master-key"
    IDENTITY_FILE    = "#{Secrets::CONFIG_DIR}/identity"

    record KeyPair, identity : String, recipient : String

    # Override the binary used for keygen (tests).
    def keygen_binary : String
      ENV["AGE_KEYGEN_BIN"]? || "age-keygen"
    end

    # Generate a new master key, store it via the appropriate
    # backend, return the public key. Refuses if a key already exists
    # (use `force: true` to overwrite — destructive).
    def generate!(force : Bool = false) : KeyPair
      maybe_migrate_keychain
      if exists? && !force
        raise Error.new("master key already exists. Use force=true to overwrite (destructive).")
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

      store_identity(identity)
      KeyPair.new(identity, recipient)
    end

    # Read the master key from the available backend. Raises
    # NotInitializedError if no key is present.
    def read : KeyPair
      maybe_migrate_keychain
      identity = read_identity
      raise NotInitializedError.new("no master key found — run `secrets init` first") unless identity
      KeyPair.new(identity, derive_recipient(identity))
    end

    # Replace the existing entry with a fresh value (used by
    # `master-key import`).
    def install!(identity : String) : KeyPair
      raise Error.new("not a valid age private key") unless identity.starts_with?("AGE-SECRET-KEY-1")
      store_identity(identity)
      KeyPair.new(identity, derive_recipient(identity))
    end

    # True if a master key is reachable through any backend.
    def exists? : Bool
      {% if flag?(:darwin) %}
        return true if KeychainMacOS.exists?(KEYCHAIN_ACCOUNT)
      {% end %}
      File.exists?(IDENTITY_FILE)
    end

    # ===== private storage routing =====================================

    # Write the identity to the platform-appropriate backend. On
    # macOS, prefer Keychain. On every other platform, fall back to
    # the identity file.
    private def self.store_identity(identity : String) : Nil
      {% if flag?(:darwin) %}
        KeychainMacOS.store(KEYCHAIN_ACCOUNT, identity)
        return
      {% end %}
      Dir.mkdir_p(Secrets::CONFIG_DIR)
      File.chmod(Secrets::CONFIG_DIR, 0o700)
      File.write(IDENTITY_FILE, identity)
      File.chmod(IDENTITY_FILE, 0o600)
    end

    # Read the identity, trying every available backend. On macOS we
    # try Keychain first, then the file (a manually-placed identity
    # file is a valid escape hatch when Keychain is locked, e.g. on
    # an SSH session into a headless Mac). Returns nil if none found.
    private def self.read_identity : String?
      {% if flag?(:darwin) %}
        if KeychainMacOS.exists?(KEYCHAIN_ACCOUNT)
          return KeychainMacOS.fetch(KEYCHAIN_ACCOUNT)
        end
      {% end %}
      return nil unless File.exists?(IDENTITY_FILE)
      File.read(IDENTITY_FILE).strip
    end

    private def self.maybe_migrate_keychain : Nil
      {% if flag?(:darwin) %}
        KeychainMacOS.migrate_legacy_if_needed!(KEYCHAIN_ACCOUNT)
      {% end %}
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
