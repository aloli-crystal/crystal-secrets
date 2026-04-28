require "./error"
require "./vault"

module CrystalSecrets
  # Paper recovery: export the age private key as a passphrase-encrypted
  # blob (printable ASCII). Used at `init` (to print and store at the
  # physical safe) and at `master-key import` after losing the Mac.
  #
  # Flow:
  #
  #   init:
  #     identity   <- MasterKey.generate!
  #     passphrase <- Diceware.generate (proposed, accepted)
  #     paper      <- Recovery.export(identity, passphrase)
  #     print(paper, passphrase)   ← user records both
  #
  #   import (new Mac):
  #     paper       <- user retypes from physical paper
  #     passphrase  <- user retypes Diceware
  #     identity    <- Recovery.import(paper, passphrase)
  #     MasterKey.install!(identity)
  module Recovery
    extend self

    # Encrypt the age private key (`AGE-SECRET-KEY-1...`) with the
    # passphrase. Returns ASCII text (PEM-like markers + base64).
    def export(identity : String, passphrase : String) : String
      raise RecoveryError.new("identity must start with AGE-SECRET-KEY-1") unless identity.starts_with?("AGE-SECRET-KEY-1")
      raise RecoveryError.new("passphrase must not be empty") if passphrase.empty?
      Vault.encrypt_with_passphrase(identity, passphrase)
    end

    # Decrypt a paper blob into the original age private key. Validates
    # that the result looks like an `AGE-SECRET-KEY-1...`.
    def import(paper : String, passphrase : String) : String
      raise RecoveryError.new("passphrase must not be empty") if passphrase.empty?
      identity = Vault.decrypt_with_passphrase(paper, passphrase).strip
      raise RecoveryError.new("decrypted blob is not an age private key") unless identity.starts_with?("AGE-SECRET-KEY-1")
      identity
    end
  end
end
