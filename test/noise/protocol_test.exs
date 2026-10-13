defmodule Noise.ProtocolTest do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Cipher
  alias Noise.Crypto.DH
  alias Noise.Crypto.Hash
  alias Noise.Protocol

  describe "from_name/1" do
    test "resolves every section of the name (spec §8)" do
      assert %Protocol{
               name: "Noise_XXpsk3_448_AESGCM_SHA512",
               dh: DH.X448,
               dhlen: 56,
               cipher: Cipher.AESGCM,
               hash: Hash.Sha512,
               hashlen: 64,
               pattern: %Noise.Pattern{name: "XXpsk3"}
             } = Protocol.from_name("Noise_XXpsk3_448_AESGCM_SHA512")

      assert %Protocol{dh: DH.X25519, dhlen: 32, cipher: Cipher.ChaChaPoly, hash: Hash.Blake2s} =
               Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2s")

      assert %Protocol{dh: DH.Secp256k1, dhlen: 33, hash: Hash.Sha256} =
               Protocol.from_name("Noise_XK_secp256k1_ChaChaPoly_SHA256")

      assert %Protocol{hash: Hash.Blake2b, hashlen: 64} =
               Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2b")
    end

    test "rejects malformed names and unsupported primitives" do
      for name <- [
            "Noise_NN_25519_ChaChaPoly",
            "Noise_NN_25519_ChaChaPoly_BLAKE2s_extra",
            "Noise_NN_P256_ChaChaPoly_BLAKE2s",
            "Noise_NN_25519_XChaChaPoly_BLAKE2s",
            "Noise_NN_25519_ChaChaPoly_SHA3",
            # pattern errors come from Noise.Pattern, tested there
            "Noise_ZZ_25519_ChaChaPoly_BLAKE2s"
          ] do
        assert_raise ArgumentError, fn -> Protocol.from_name(name) end
      end
    end

    test "rejects names over 255 bytes (spec §8)" do
      name = fn reps ->
        "Noise_XXpsk0" <> String.duplicate("+psk3", reps) <> "_448_AESGCM_SHA256"
      end

      # No supported name reaches 255 bytes, so the boundary name fails on its
      # repeated modifiers rather than on length.
      assert byte_size(name.(45)) == 255
      error = assert_raise ArgumentError, fn -> Protocol.from_name(name.(45)) end
      refute error.message =~ "at most 255 bytes"

      assert_raise ArgumentError, ~r/at most 255 bytes/, fn -> Protocol.from_name(name.(46)) end
    end
  end
end
