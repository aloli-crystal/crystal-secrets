require "process"
require "file_utils"
require "random/secure"
require "./error"

module CrystalSecrets
  # Vault encryption / decryption via shell-out to the `age(1)` binary
  # (https://age-encryption.org).
  #
  # v0.1 supports single-recipient only. Both encrypt and decrypt are
  # streaming via stdin/stdout — the plaintext is never written to a
  # disk file. The identity (private key) is briefly written to a
  # mode-0600 temp file because `age -i` requires a path; the file is
  # deleted as soon as `age` returns.
  module Vault
    extend self

    # Override at runtime (tests).
    def binary : String
      ENV["AGE_BIN"]? || "age"
    end

    # Where to put the brief identity tempfile. macOS doesn't expose a
    # tmpfs by default; /tmp is fine for a sub-100ms exposure.
    def tmpdir : String
      ENV["CRYSTAL_SECRETS_TMPDIR"]? || (ENV["TMPDIR"]? || "/tmp")
    end

    # Encrypt `plaintext` to ASCII-armored age PEM for `recipient`
    # (a public key string starting with "age1...").
    def encrypt(plaintext : String, recipient : String) : String
      raise VaultError.new("recipient must start with 'age1'") unless recipient.starts_with?("age1")

      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run(binary, [
        "--armor",
        "--encrypt",
        "--recipient", recipient,
      ],
        input: IO::Memory.new(plaintext),
        output: stdout,
        error: stderr)
      raise VaultError.new("age encrypt failed: #{stderr.to_s.strip}") unless status.success?
      stdout.to_s
    end

    # Decrypt `ciphertext` (ASCII-armored age PEM) using `identity`
    # (an "AGE-SECRET-KEY-1..." private key string). Returns the
    # plaintext as a String.
    def decrypt(ciphertext : String, identity : String) : String
      raise VaultError.new("identity must start with 'AGE-SECRET-KEY-1'") unless identity.starts_with?("AGE-SECRET-KEY-1")

      with_identity_file(identity) do |path|
        stdout = IO::Memory.new
        stderr = IO::Memory.new
        status = Process.run(binary, [
          "--decrypt",
          "--identity", path,
        ],
          input: IO::Memory.new(ciphertext),
          output: stdout,
          error: stderr)
        raise VaultError.new("age decrypt failed: #{stderr.to_s.strip}") unless status.success?
        stdout.to_s
      end
    end

    # Encrypt with a passphrase (used for the recovery paper export).
    # `age -p` prompts via /dev/tty; we feed the passphrase on a
    # second pipe via the AGE_PASSPHRASE env var when available, or
    # via a tty wrapper. Simplest robust path: shell-out to `age -p`
    # with the passphrase fed twice on stdin (age prompts then asks
    # for confirmation when encrypting).
    # Encrypt with a passphrase (used for the recovery paper export).
    #
    # Why not `age -p`? Because `age -p` insists on reading the
    # passphrase from /dev/tty, which can't be fed without spawning
    # a pseudo-terminal. For the paper recovery use case we use
    # `openssl enc` with PBKDF2 (600 000 iterations, SHA-256,
    # AES-256-CBC), which accepts the passphrase via
    # `-pass pass:STRING` directly. `openssl` is available on every
    # Unix-like system (LibreSSL on macOS, OpenSSL on Linux/FreeBSD).
    #
    # The output is base64-armored and wrapped in PEM-like markers
    # so the paper format is clearly identifiable.
    def encrypt_with_passphrase(plaintext : String, passphrase : String) : String
      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run("openssl", [
        "enc", "-aes-256-cbc",
        "-pbkdf2", "-iter", "600000",
        "-md", "sha256",
        "-salt",
        "-a",
        "-pass", "pass:#{passphrase}",
      ],
        input: IO::Memory.new(plaintext),
        output: stdout,
        error: stderr)
      raise VaultError.new("openssl encrypt failed: #{stderr.to_s.strip}") unless status.success?

      String.build do |io|
        io << "-----BEGIN CRYSTAL-SECRETS RECOVERY-----\n"
        io << stdout.to_s
        io << "-----END CRYSTAL-SECRETS RECOVERY-----\n"
      end
    end

    # Decrypt a passphrase-encrypted recovery paper blob.
    def decrypt_with_passphrase(ciphertext : String, passphrase : String) : String
      lines = ciphertext.lines(chomp: false).reject do |l|
        l.starts_with?("-----BEGIN CRYSTAL-SECRETS RECOVERY-----") ||
          l.starts_with?("-----END CRYSTAL-SECRETS RECOVERY-----")
      end
      payload = lines.join

      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run("openssl", [
        "enc", "-aes-256-cbc",
        "-d",
        "-pbkdf2", "-iter", "600000",
        "-md", "sha256",
        "-a",
        "-pass", "pass:#{passphrase}",
      ],
        input: IO::Memory.new(payload),
        output: stdout,
        error: stderr)
      raise VaultError.new("openssl decrypt failed: #{stderr.to_s.strip}") unless status.success?
      stdout.to_s
    end

    # ==== private helpers =================================================

    private def self.with_identity_file(identity : String, &)
      path = File.join(tmpdir, "cs-id-#{Random::Secure.hex(8)}")
      File.write(path, identity)
      File.chmod(path, 0o600)
      begin
        yield path
      ensure
        # Best-effort wipe + delete
        begin
          File.open(path, "w") { |f| f.write(Bytes.new(identity.bytesize, 0_u8)) }
        rescue
          # ignore
        end
        File.delete(path) if File.exists?(path)
      end
    end

    private def self.with_temp_file(content : String, suffix : String, &)
      path = File.join(tmpdir, "cs-#{Random::Secure.hex(8)}#{suffix}")
      File.write(path, content)
      File.chmod(path, 0o600)
      begin
        yield path
      ensure
        File.delete(path) if File.exists?(path)
      end
    end
  end
end
