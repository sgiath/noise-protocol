defmodule NoiseTest do
  use ExUnit.Case, async: true

  alias Noise.CipherState

  doctest Noise

  @xx "Noise_XX_25519_ChaChaPoly_BLAKE2s"

  # Runs the whole XX handshake and returns both completed states.
  defp complete_xx(prologue \\ "") do
    protocol = Noise.protocol(@xx)
    client_kp = Noise.generate_keypair(protocol)
    server_kp = Noise.generate_keypair(protocol)

    client = Noise.handshake(protocol, true, prologue, s: client_kp)
    server = Noise.handshake(protocol, false, prologue, s: server_kp)

    {:ok, m1, client} = Noise.handshake_step(client, "hello")
    {:ok, "hello", server} = Noise.handshake_step(server, m1)
    {:ok, m2, server} = Noise.handshake_step(server, "")
    {:ok, "", client} = Noise.handshake_step(client, m2)
    {:complete, m3, client} = Noise.handshake_step(client, "bye")
    {:complete, "bye", server} = Noise.handshake_step(server, m3)

    {client, server, client_kp, server_kp}
  end

  test "XX handshake: hashes agree, statics are learned, transport works both ways" do
    {client, server, {_, client_pub}, {_, server_pub}} = complete_xx("prologue")

    assert Noise.handshake_hash(client) == Noise.handshake_hash(server)
    assert Noise.remote_static(server) == client_pub
    assert Noise.remote_static(client) == server_pub

    {client_tx, client_rx} = Noise.split(client)
    {server_tx, server_rx} = Noise.split(server)

    {:ok, c1, client_tx} = Noise.encrypt(client_tx, "to server")
    {:ok, "to server", server_rx} = Noise.decrypt(server_rx, c1)
    {:ok, c2, _server_tx} = Noise.encrypt(server_tx, "to client")
    {:ok, "to client", _client_rx} = Noise.decrypt(client_rx, c2)

    # split is role-aware: the client's send state must not decrypt its own traffic
    {:ok, c3, _} = Noise.encrypt(client_tx, "again")
    assert {:error, :decrypt_failed} = Noise.decrypt(server_rx, c1)
    assert {:ok, "again", _} = Noise.decrypt(server_rx, c3)
  end

  test "explicit write_message/read_message tag the final message as complete" do
    protocol = Noise.protocol("Noise_NN_25519_AESGCM_SHA256")
    init = Noise.handshake(protocol, true)
    resp = Noise.handshake(protocol, false)

    {:ok, m1, init} = Noise.write_message(init, "")
    {:ok, "", resp} = Noise.read_message(resp, m1)
    {:complete, m2, _resp} = Noise.write_message(resp, "")
    {:complete, "", init} = Noise.read_message(init, m2)
    assert {:error, :handshake_complete} = Noise.handshake_step(init, "")
  end

  test "handshake_hash raises until the handshake is complete" do
    init = Noise.handshake("Noise_NN_25519_AESGCM_SHA256", true)
    assert_raise ArgumentError, ~r/not complete/, fn -> Noise.handshake_hash(init) end
  end

  test "one-way split exposes only the initiator-to-responder direction (spec §7.4)" do
    protocol = Noise.protocol("Noise_N_25519_ChaChaPoly_BLAKE2s")
    {_, server_pub} = server_kp = Noise.generate_keypair(protocol)

    sender = Noise.handshake(protocol, true, "", rs: server_pub)
    recipient = Noise.handshake(protocol, false, "", s: server_kp)
    {:complete, m1, sender} = Noise.handshake_step(sender, "")
    {:complete, "", recipient} = Noise.handshake_step(recipient, m1)

    assert {tx, sender_rx} = Noise.split(sender)
    assert {recipient_tx, rx} = Noise.split(recipient)

    {:ok, c, _} = Noise.encrypt(tx, "one way")
    assert {:ok, "one way", _} = Noise.decrypt(rx, c)

    # the missing direction is nil and refuses every transport operation
    for missing <- [sender_rx, recipient_tx] do
      assert missing == nil
      assert_raise ArgumentError, ~r/no cipher state/, fn -> Noise.encrypt(missing, "x") end
      assert_raise ArgumentError, ~r/no cipher state/, fn -> Noise.decrypt(missing, c) end
      assert_raise ArgumentError, ~r/no cipher state/, fn -> Noise.rekey(missing) end
    end
  end

  describe "transport" do
    # Built directly, as Noise.split/1 would return it: the nonce and rekey
    # rules themselves are tested at the Noise.CipherState interface.
    setup do
      protocol = Noise.protocol(@xx)
      cs = protocol |> CipherState.initialize() |> CipherState.initialize_key(<<7::256>>)
      {:ok, protocol: protocol, tx: cs, rx: cs}
    end

    test "messages are bounded at 65535 bytes including the tag (spec §3)", %{tx: tx, rx: rx} do
      assert {:ok, ciphertext, _} = Noise.encrypt(tx, :binary.copy(<<0>>, 65_519))
      assert byte_size(ciphertext) == 65_535
      assert {:ok, _, _} = Noise.decrypt(rx, ciphertext)
      assert {:error, :message_too_long} = Noise.encrypt(tx, :binary.copy(<<0>>, 65_520))
      assert {:error, :message_too_long} = Noise.decrypt(rx, <<0::size(65_536 * 8)>>)
    end

    test "keyless cipher state is refused", %{protocol: protocol} do
      cs = CipherState.initialize(protocol)
      assert_raise ArgumentError, fn -> Noise.encrypt(cs, "plaintext") end
      assert_raise ArgumentError, fn -> Noise.decrypt(cs, "ciphertext") end
      assert_raise ArgumentError, fn -> Noise.rekey(cs) end
    end
  end

  test "unsupported protocol names raise ArgumentError" do
    for name <- [
          "Noise_NN_25519_ChaChaPoly",
          "Noise_NN_25519_ChaChaPoly_BLAKE2s_extra",
          "Noise_ZZ_25519_ChaChaPoly_BLAKE2s",
          "Noise_NN_P256_ChaChaPoly_BLAKE2s",
          "Noise_NN_25519_XChaChaPoly_BLAKE2s",
          "Noise_NN_25519_ChaChaPoly_SHA3",
          "Noise_NNpsk3_25519_ChaChaPoly_BLAKE2s",
          "Noise_NNfallback_25519_ChaChaPoly_BLAKE2s"
        ] do
      assert_raise ArgumentError, fn -> Noise.protocol(name) end
    end
  end

  test "protocol names over 255 bytes are rejected (spec §8)" do
    name = fn reps ->
      "Noise_XXpsk0" <> String.duplicate("+psk3", reps) <> "_448_AESGCM_SHA256"
    end

    # No supported name reaches 255 bytes, so the boundary name fails on its
    # repeated modifiers rather than on length.
    assert byte_size(name.(45)) == 255
    error = assert_raise ArgumentError, fn -> Noise.protocol(name.(45)) end
    refute error.message =~ "at most 255 bytes"

    assert_raise ArgumentError, ~r/at most 255 bytes/, fn -> Noise.protocol(name.(46)) end
  end
end
