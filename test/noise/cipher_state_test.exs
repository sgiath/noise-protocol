defmodule Noise.CipherStateTest do
  use ExUnit.Case, async: true

  alias Noise.CipherState
  alias Noise.Protocol

  @key <<7::256>>
  @max_nonce 0xFFFF_FFFF_FFFF_FFFF

  setup do
    protocol = Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2b")

    {:ok,
     protocol: protocol, keyed: CipherState.initialize_key(CipherState.initialize(protocol), @key)}
  end

  test "initialize has no key", %{protocol: protocol} do
    refute CipherState.has_key?(CipherState.initialize(protocol))
  end

  test "initialize_key sets key and resets nonce", %{keyed: state} do
    assert CipherState.has_key?(state)
    assert CipherState.nonce(state) == 0

    state = CipherState.set_nonce(state, 5)
    assert CipherState.nonce(CipherState.initialize_key(state, @key)) == 0
  end

  test "initialize_key rejects keys that are not 32 bytes", %{protocol: protocol} do
    assert_raise FunctionClauseError, fn ->
      CipherState.initialize_key(CipherState.initialize(protocol), <<1, 2, 3>>)
    end
  end

  test "encrypt then decrypt round-trips and increments nonce", %{keyed: state} do
    {:ok, ciphertext, tx} = CipherState.encrypt_with_ad(state, "ad", "plaintext")
    assert ciphertext != "plaintext"
    assert CipherState.nonce(tx) == 1

    {:ok, "plaintext", rx} = CipherState.decrypt_with_ad(state, "ad", ciphertext)
    assert CipherState.nonce(rx) == 1
  end

  test "decrypt failure returns error and does not advance the nonce (spec §5.1)", %{keyed: state} do
    {:ok, ciphertext, _} = CipherState.encrypt_with_ad(state, "", "plaintext")
    size = byte_size(ciphertext) - 1
    <<prefix::binary-size(^size), last>> = ciphertext
    tampered = <<prefix::binary, Bitwise.bxor(last, 1)>>

    assert {:error, :decrypt_failed} = CipherState.decrypt_with_ad(state, "", tampered)
    assert {:error, :decrypt_failed} = CipherState.decrypt_with_ad(state, "wrong ad", ciphertext)
    assert {:error, :decrypt_failed} = CipherState.decrypt_with_ad(state, "", <<1, 2, 3>>)

    # the same state still decrypts the genuine message at nonce 0
    assert {:ok, "plaintext", _} = CipherState.decrypt_with_ad(state, "", ciphertext)
  end

  test "nonce 2^64-1 is reserved: encrypt and decrypt fail (spec §5.1)", %{keyed: state} do
    state = CipherState.set_nonce(state, @max_nonce - 1)
    {:ok, _ciphertext, state} = CipherState.encrypt_with_ad(state, "", "last one")
    assert CipherState.nonce(state) == @max_nonce

    assert {:error, :nonce_exhausted} = CipherState.encrypt_with_ad(state, "", "one too many")
    assert {:error, :nonce_exhausted} = CipherState.decrypt_with_ad(state, "", <<0::256>>)
  end

  test "set_nonce rejects out-of-range values", %{keyed: state} do
    assert_raise ArgumentError, fn -> CipherState.set_nonce(state, -1) end
    assert_raise ArgumentError, fn -> CipherState.set_nonce(state, @max_nonce) end
    assert_raise ArgumentError, fn -> CipherState.set_nonce(state, 1.0) end
  end

  test "keyless state passes data through unchanged", %{protocol: protocol} do
    state = CipherState.initialize(protocol)
    assert {:ok, "plaintext", ^state} = CipherState.encrypt_with_ad(state, "ad", "plaintext")
    assert {:ok, "ciphertext", ^state} = CipherState.decrypt_with_ad(state, "ad", "ciphertext")
  end

  test "rekey changes the key, keeps the nonce, and both sides agree", %{keyed: state} do
    state = CipherState.set_nonce(state, 3)
    rekeyed = CipherState.rekey(state)

    assert CipherState.nonce(rekeyed) == 3
    {:ok, ciphertext, _} = CipherState.encrypt_with_ad(rekeyed, "", "hi")
    assert {:error, :decrypt_failed} = CipherState.decrypt_with_ad(state, "", ciphertext)
    assert {:ok, "hi", _} = CipherState.decrypt_with_ad(CipherState.rekey(state), "", ciphertext)
  end

  test "inspect never shows the key", %{keyed: state} do
    refute inspect(state, limit: :infinity) =~ inspect(@key, limit: :infinity)
  end
end
