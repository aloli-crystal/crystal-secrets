require "file_utils"
require "./error"

module Secrets
  # Append-only audit log of mutations on a vault. One file per vault
  # under `${CONFIG_DIR}/audit/<vault>.log`, mode 0600. Each line is
  # tab-separated:
  #
  #   <RFC3339 UTC timestamp> \t <user> \t <op> \t <key|->
  #
  # Operations recorded: `set`, `delete`, `edit`, `rotation`, `create`.
  # `key` is `-` for whole-vault operations (edit, rotation, create).
  #
  # The log is *append-only* in spirit (we never rewrite existing
  # lines) but not tamper-proof — an attacker with write access to the
  # log can edit it. The intent is operator-side audit ("when did I
  # last touch this vault?"), not security boundary.
  module Audit
    extend self

    AUDIT_DIR = "#{Secrets::CONFIG_DIR}/audit"

    # Append a single audit line for `op` on `vault`. `key` is the
    # specific entry touched, or nil for a vault-wide operation.
    def log(vault : String, op : String, key : String? = nil) : Nil
      Dir.mkdir_p(AUDIT_DIR)
      File.chmod(AUDIT_DIR, 0o700)
      path = log_path(vault)
      user = ENV["USER"]? || "unknown"
      line = [Time.utc.to_rfc3339, user, op, key || "-"].join("\t")
      File.open(path, "a") { |f| f.puts line }
      File.chmod(path, 0o600)
    end

    # Read the full audit log for `vault`. Returns an empty array if
    # no operation has ever been recorded.
    def read(vault : String) : Array(String)
      path = log_path(vault)
      return [] of String unless File.exists?(path)
      File.read_lines(path)
    end

    # Absolute path to the per-vault audit log file.
    def log_path(vault : String) : String
      File.join(AUDIT_DIR, "#{vault}.log")
    end
  end
end
