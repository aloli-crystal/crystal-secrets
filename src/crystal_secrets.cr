require "crystal-toml"
# crystal-diceware ships its entry as `crystal_diceware.cr` (snake)
# while the shard name uses dashes — bypass the default lookup with
# the explicit subpath form.
require "crystal-diceware/crystal_diceware"

require "./crystal_secrets/version"
require "./crystal_secrets/error"
require "./crystal_secrets/platform/keychain_macos"
require "./crystal_secrets/vault"
require "./crystal_secrets/master_key"
require "./crystal_secrets/recovery"

module CrystalSecrets
end
