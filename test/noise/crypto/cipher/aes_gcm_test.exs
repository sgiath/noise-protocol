defmodule Noise.Crypto.Cipher.AESGCMTest do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Cipher.AESGCM

  @k :crypto.strong_rand_bytes(32)

  test "round trip" do
    cipher_text = AESGCM.encrypt(@k, 0, "associated data", "hello world")
    assert byte_size(cipher_text) == byte_size("hello world") + 16
    assert AESGCM.decrypt(@k, 0, "associated data", cipher_text) == "hello world"
  end

  test "nonce is encoded big-endian in the low 8 bytes (spec §12.4)" do
    {expected, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, @k, <<0::32, 1::big-64>>, "x", "", true)

    assert AESGCM.encrypt(@k, 1, "", "x") == expected <> tag
  end

  test "wrong key, wrong ad, wrong nonce and short input return :error" do
    cipher_text = AESGCM.encrypt(@k, 0, "ad1", "hello")
    assert AESGCM.decrypt(:crypto.strong_rand_bytes(32), 0, "ad1", cipher_text) == :error
    assert AESGCM.decrypt(@k, 0, "ad2", cipher_text) == :error
    assert AESGCM.decrypt(@k, 1, "ad1", cipher_text) == :error
    assert AESGCM.decrypt(@k, 0, "ad1", <<1, 2, 3>>) == :error
  end

  test "rekey is ENCRYPT(k, 2^64-1, zerolen, zeros[32]) truncated to 32 bytes (spec §4.2)" do
    k = Base.decode16!("E68F69B7F096D7917245F5E5CF8AE1595FEBE4D4644333C99F9C4A1282031C9F")

    assert AESGCM.rekey(k) ==
             Base.decode16!("C2EF793F01F84B310352948861D6713A9966D996617E4FBFBE545A335370E163")
  end
end
