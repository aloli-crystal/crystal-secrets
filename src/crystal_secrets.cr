require "crystal-toml"
require "crystal-diceware/diceware"

require "./crystal_secrets/version"
require "./crystal_secrets/error"
require "./crystal_secrets/platform/keychain_macos"
require "./crystal_secrets/vault"
require "./crystal_secrets/master_key"
require "./crystal_secrets/recovery"

module CrystalSecrets
end
