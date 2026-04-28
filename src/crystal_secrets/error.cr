module CrystalSecrets
  class Error < Exception
  end

  class NotInitializedError < Error
  end

  class KeychainError < Error
  end

  class VaultError < Error
  end

  class TomlError < Error
  end

  class DicewareError < Error
  end

  class RecoveryError < Error
  end
end
