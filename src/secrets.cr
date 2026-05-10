require "toml"
require "diceware"

require "./secrets/version"
require "./secrets/error"

module Secrets
  # Centralised XDG-aware paths. Used by `Secrets::CLI` for vault
  # storage and by `Secrets::Audit` for the per-vault append-only log.
  # Honours `XDG_CONFIG_HOME` (cf. memory feedback_xdg_config_convention.md).
  XDG_CONFIG_HOME = ENV["XDG_CONFIG_HOME"]? || "#{ENV["HOME"]}/.config"
  CONFIG_DIR      = "#{XDG_CONFIG_HOME}/secrets"
end

require "./secrets/platform/keychain_macos"
require "./secrets/vault"
require "./secrets/master_key"
require "./secrets/recovery"
require "./secrets/audit"
require "./secrets/editor"
