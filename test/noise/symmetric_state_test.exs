defmodule Noise.SymmetricStateTest do
  use ExUnit.Case, async: true

  alias Noise.CipherState
  alias Noise.Protocol
  alias Noise.SymmetricState

  setup do
    protocol = Protocol.from_name("Noise_NN_25519_ChaChaPoly_BLAKE2b")
    keyed = protocol |> SymmetricState.initialize() |> SymmetricState.mix_key(<<0::256>>)
    {:ok, protocol: protocol, keyed: keyed}
  end

  test "short protocol name is zero-padded into h (spec §5.2)", %{protocol: protocol} do
    h = protocol |> SymmetricState.initialize() |> SymmetricState.handshake_hash()
    name_len = byte_size(protocol.name)
    padding = (protocol.hashlen - name_len) * 8

    assert h == <<protocol.name::binary, 0::size(padding)>>
  end

  test "protocol name longer than HASHLEN is hashed into h (spec §5.2)" do
    protocol = Protocol.from_name("Noise_XXpsk0+psk1+psk2+psk3_25519_ChaChaPoly_SHA256")
    assert byte_size(protocol.name) > 32

    h = protocol |> SymmetricState.initialize() |> SymmetricState.handshake_hash()
    assert h == :crypto.hash(:sha256, protocol.name)
  end

  test "mix_key installs a cipher key", %{protocol: protocol, keyed: keyed} do
    refute SymmetricState.has_key?(SymmetricState.initialize(protocol))
    assert SymmetricState.has_key?(keyed)
  end

  test "encrypt_and_hash / decrypt_and_hash round-trip and agree on h", %{keyed: state} do
    {:ok, ciphertext, sender} = SymmetricState.encrypt_and_hash(state, "hello")
    assert byte_size(ciphertext) == 5 + 16

    {:ok, "hello", receiver} = SymmetricState.decrypt_and_hash(state, ciphertext)
    assert SymmetricState.handshake_hash(sender) == SymmetricState.handshake_hash(receiver)
  end

  test "decrypt_and_hash failure leaves the state untouched", %{keyed: state} do
    {:ok, ciphertext, _} = SymmetricState.encrypt_and_hash(state, "hello")
    tampered = <<0>> <> binary_part(ciphertext, 1, byte_size(ciphertext) - 1)

    assert {:error, :decrypt_failed} = SymmetricState.decrypt_and_hash(state, tampered)
    assert {:ok, "hello", _} = SymmetricState.decrypt_and_hash(state, ciphertext)
  end

  # One chain of operations under Noise_NN_25519_ChaChaPoly_SHA512. HASHLEN is
  # 64, so every derived cipher key is a truncated HKDF output. Expected values
  # were computed from spec §4-§5 with Python's hashlib, hmac and the
  # `cryptography` package's ChaCha20Poly1305, after checking that code
  # against the cacophony vector for the same protocol.
  describe "known answers" do
    setup do
      protocol = Protocol.from_name("Noise_NN_25519_ChaChaPoly_SHA512")
      {:ok, initialized: SymmetricState.initialize(protocol)}
    end

    test "mix_hash sets h to HASH(h || data)", %{initialized: initialized} do
      assert h(SymmetricState.mix_hash(initialized, "prologue")) ==
               "91cd6250aad9eb1ec51b5b76536d2aaca47ea6658faaaccc708aa88821b7ec78" <>
                 "ad75ae88047386f882f26d0d5c0f8882e66697970bf38751dbb28e3fd032d5e6"
    end

    test "mix_key keys the cipher and encrypt_and_hash mixes each ciphertext into h",
         %{initialized: initialized} do
      {:ok, c1, state} = SymmetricState.encrypt_and_hash(keyed(initialized), "hello")
      assert c1 == hex("893b3ad326923540aca79b1bcb0f1f0a0e8c8afd0b")

      assert h(state) ==
               "896e2b1cbe9aa8d9bca50db5dbae10a106bd0674574833e4cb35b1724304575f" <>
                 "596299564dcf94793bc5bbae9a0b383db9632a5042682e2e5f307edf38457b28"

      # the second message uses nonce 1
      {:ok, c2, state} = SymmetricState.encrypt_and_hash(state, "again")
      assert c2 == hex("4d2c91d91371cdde21f7cadcbf0b972cbf590b02b1")

      assert h(state) ==
               "875a8be1f9357578d2a9f99d74a1ec1c28d3f99cb2ffbc4eb2cfa7172651df2a" <>
                 "497e2158a00f8fb338cef7563920c60bb0fffc8756fe8518da835577dedd6729"
    end

    test "mix_key_and_hash mixes temp_h into h and rekeys with nonce 0",
         %{initialized: initialized} do
      state = psk_mixed(initialized)

      assert h(state) ==
               "2cd65cadb29b7851e9b70281b079d545ab0ca4477a815537cb3806c68e498725" <>
                 "c43e9f047b3d9b5b2aef1ce21e1d07263bc263b4dc06dbfc864348b8f57f0a9a"

      {:ok, c3, state} = SymmetricState.encrypt_and_hash(state, "")
      assert c3 == hex("6d6ec60449db9d8b12b9895d23a691d3")

      assert h(state) ==
               "d902ec9072cde18bfdbb5fd6f005c69da457e7ce10ff167c43c45b3ea2d7eb1c" <>
                 "f947503093ce6135cb347f09df8ea1827fc2f4fb8a959fdedd43fc6b997b1e15"
    end

    test "split derives the initiator and responder keys from ck",
         %{initialized: initialized} do
      {:ok, _, state} = SymmetricState.encrypt_and_hash(psk_mixed(initialized), "")
      {c1, c2} = SymmetricState.split(state)

      assert {:ok, t1, _} = CipherState.encrypt_with_ad(c1, "", "to responder")
      assert t1 == hex("b7fe8dec97073ebe1ddeae09e3fdef2d52dd474058763e99f7502619")

      assert {:ok, t2, _} = CipherState.encrypt_with_ad(c2, "", "to initiator")
      assert t2 == hex("c0efd2577e38ac7ba069a464cd304466116a22141759c7daa4a024d9")
    end
  end

  defp hex(h), do: Base.decode16!(h, case: :lower)
  defp h(state), do: state |> SymmetricState.handshake_hash() |> Base.encode16(case: :lower)

  defp keyed(initialized) do
    initialized
    |> SymmetricState.mix_hash("prologue")
    |> SymmetricState.mix_key(:binary.copy(<<0x01>>, 32))
  end

  defp psk_mixed(initialized) do
    {:ok, _, state} = SymmetricState.encrypt_and_hash(keyed(initialized), "hello")
    {:ok, _, state} = SymmetricState.encrypt_and_hash(state, "again")
    SymmetricState.mix_key_and_hash(state, :binary.copy(<<0x02>>, 32))
  end
end
