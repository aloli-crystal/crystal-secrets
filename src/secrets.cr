require "toml"
require "diceware"

require "./secrets/version"
require "./secrets/error"
require "./secrets/platform/keychain_macos"
require "./secrets/vault"
require "./secrets/master_key"
require "./secrets/recovery"

module Secrets
end
