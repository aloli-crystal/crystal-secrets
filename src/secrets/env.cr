require "process"
require "file_utils"
require "./error"

module Secrets
  # `.env` ↔ `.env.age` operations: file-to-file encryption with the
  # current recipient roster, and `exec` which decrypts in memory and
  # spawns a process with the parsed KEY=VALUE pairs injected into
  # its environment — never writes the plaintext to disk.
  #
  # The plaintext format is the de-facto Bourne-shell `.env` flavour:
  #
  #   # comments
  #   KEY=value
  #   KEY="quoted value"
  #   KEY='single-quoted'
  #   export KEY=value          # `export` prefix accepted, ignored
  #
  # Multi-line values, command substitution, and ${VAR} expansion are
  # *not* supported. This is by design — a vault is a flat keystore,
  # not a shell init file.
  module Env
    extend self

    # Encrypt `src_path` (a plaintext .env) to `dest_path` (defaults
    # to `${src_path}.age`). The destination is mode 0600.
    def encrypt_file(src_path : String, dest_path : String? = nil) : String
      raise Error.new("source file not found: #{src_path}") unless File.exists?(src_path)
      target = dest_path || "#{src_path}.age"
      plaintext = File.read(src_path)
      ciphertext = Vault.encrypt(plaintext, Recipients.encryption_keys)
      File.write(target, ciphertext)
      File.chmod(target, 0o600)
      target
    end

    # Decrypt `enc_path` (a ciphertext .env.age) to `dest_path`
    # (defaults to `enc_path` minus the `.age` suffix). The output is
    # mode 0600. Use sparingly on a server — the goal of this shard
    # is to *not* let plaintext .env files exist on disk; prefer
    # `Env.exec` for the runtime case.
    def decrypt_file(enc_path : String, dest_path : String? = nil) : String
      raise Error.new("encrypted file not found: #{enc_path}") unless File.exists?(enc_path)
      target = dest_path || begin
        enc_path.ends_with?(".age") ? enc_path.rchop(".age") : "#{enc_path}.dec"
      end
      identity = MasterKey.read.identity
      ciphertext = File.read(enc_path)
      plaintext = Vault.decrypt(ciphertext, identity)
      File.write(target, plaintext)
      File.chmod(target, 0o600)
      target
    end

    # Decrypt `enc_path` in memory, parse it as `.env`, exec `command`
    # with the parsed KEY=VALUE pairs added to its environment.
    # `Process.exec` replaces the current process image — no
    # plaintext is ever written to disk and the .env contents leave
    # memory once the new image takes over. This is the recommended
    # way to start a server-side service.
    #
    # Returns Int32 only on failure (the exec branch never returns).
    def exec(enc_path : String, command : String, args : Array(String)) : Int32
      raise Error.new("encrypted file not found: #{enc_path}") unless File.exists?(enc_path)
      identity = MasterKey.read.identity
      ciphertext = File.read(enc_path)
      plaintext = Vault.decrypt(ciphertext, identity)

      env = parse(plaintext)
      env.each { |k, v| ENV[k] = v }

      # `Process.exec` raises on failure (e.g. command not found) and
      # replaces the image on success — we never see the next line.
      Process.exec(command, args)
      0
    end

    # Parse `.env`-style content into a Hash. Whitespace is stripped,
    # comments and empty lines are ignored, an optional leading
    # `export ` is allowed.
    def parse(content : String) : Hash(String, String)
      result = {} of String => String
      content.each_line do |raw|
        line = raw.strip
        next if line.empty?
        next if line.starts_with?('#')
        line = line.sub(/^export\s+/, "")
        eq = line.index('=')
        next unless eq # malformed lines silently skipped
        key = line[0...eq].strip
        value = line[(eq + 1)..-1].strip
        next if key.empty?
        # Strip matching surrounding quotes (single or double).
        if (value.size >= 2) &&
           ((value.starts_with?('"') && value.ends_with?('"')) ||
           (value.starts_with?('\'') && value.ends_with?('\'')))
          value = value[1...-1]
        end
        result[key] = value
      end
      result
    end
  end
end
