require "process"
require "../error"

module Secrets
  # macOS Keychain backend, via shell-out to `/usr/bin/security`.
  #
  # The key material is fed/read through stdin/stdout — never through
  # `argv` (which would leak via `ps`). Each entry uses a fixed
  # `service` (= the shard's bundle id) and a caller-chosen `account`
  # to disambiguate (e.g. "master-key").
  module KeychainMacOS
    extend self

    SERVICE        = "dev.aloli.secrets"
    LEGACY_SERVICE = "dev.aloli.crystal-secrets"

    # Override at runtime (tests use a fake script).
    def binary : String
      ENV["SECURITY_BIN"]? || "/usr/bin/security"
    end

    # Store (or update) a generic password under (SERVICE, account).
    # The value is passed via stdin (`-w -`), never via argv.
    def store(account : String, value : String) : Nil
      args = [binary, "add-generic-password",
              "-a", account,
              "-s", SERVICE,
              "-w", # password value follows; use "-" to read from stdin
              "-",
              "-U"] # update if it exists already
      run_with_stdin!(args, value)
    end

    # Retrieve the value as a raw string. Raises KeychainError if absent.
    def fetch(account : String) : String
      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run(binary, [
        "find-generic-password",
        "-a", account,
        "-s", SERVICE,
        "-w",
      ], output: stdout, error: stderr)
      raise KeychainError.new("keychain entry not found for account=#{account}") unless status.success?
      stdout.to_s.chomp
    end

    # True if (SERVICE, account) currently has an entry.
    def exists?(account : String) : Bool
      status = Process.run(binary, [
        "find-generic-password",
        "-a", account,
        "-s", SERVICE,
        "-g", # would print to stderr; we discard
      ], output: Process::Redirect::Close, error: Process::Redirect::Close)
      status.success?
    end

    # Remove the entry for (SERVICE, account). No-op if absent.
    def delete(account : String) : Nil
      Process.run(binary, [
        "delete-generic-password",
        "-a", account,
        "-s", SERVICE,
      ], output: Process::Redirect::Close, error: Process::Redirect::Close)
    end

    # Transparent rename migration — Keychain entries created before
    # the v0.2.6 rename live under LEGACY_SERVICE ("dev.aloli.crystal-secrets").
    # If a caller looks up `account` under SERVICE and finds nothing, but
    # the entry exists under LEGACY_SERVICE, this method copies it to
    # SERVICE then deletes the legacy one. Idempotent and safe to call
    # on every read path. Returns true if a migration happened.
    def migrate_legacy_if_needed!(account : String) : Bool
      return false if exists?(account)
      return false unless legacy_exists?(account)

      legacy_value = legacy_fetch(account)
      store(account, legacy_value)
      legacy_delete(account)
      true
    end

    private def legacy_exists?(account : String) : Bool
      status = Process.run(binary, [
        "find-generic-password",
        "-a", account,
        "-s", LEGACY_SERVICE,
        "-g",
      ], output: Process::Redirect::Close, error: Process::Redirect::Close)
      status.success?
    end

    private def legacy_fetch(account : String) : String
      stdout = IO::Memory.new
      stderr = IO::Memory.new
      status = Process.run(binary, [
        "find-generic-password",
        "-a", account,
        "-s", LEGACY_SERVICE,
        "-w",
      ], output: stdout, error: stderr)
      raise KeychainError.new("legacy keychain entry vanished mid-migration for account=#{account}") unless status.success?
      stdout.to_s.chomp
    end

    private def legacy_delete(account : String) : Nil
      Process.run(binary, [
        "delete-generic-password",
        "-a", account,
        "-s", LEGACY_SERVICE,
      ], output: Process::Redirect::Close, error: Process::Redirect::Close)
    end

    private def run_with_stdin!(args : Array(String), payload : String) : Nil
      stderr = IO::Memory.new
      status = Process.run(args[0], args[1..-1],
        input: IO::Memory.new(payload),
        output: Process::Redirect::Close,
        error: stderr)
      unless status.success?
        raise KeychainError.new("#{args.join(' ')} failed (exit #{status.exit_code}): #{stderr.to_s.strip}")
      end
    end
  end
end
