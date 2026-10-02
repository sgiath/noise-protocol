defmodule NoiseTest do
  use ExUnit.Case, async: true

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

  test "explicit write_message/read_message enforce turns" do
    protocol = Noise.protocol("Noise_NN_25519_AESGCM_SHA256")
    init = Noise.handshake(protocol, true)
    resp = Noise.handshake(protocol, false)

    assert {:error, :wrong_turn} = Noise.write_message(resp, "")
    assert {:error, :wrong_turn} = Noise.read_message(init, <<0::256>>)

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

  describe "hostile input" do
    setup do
      protocol = Noise.protocol(@xx)
      client = Noise.handshake(protocol, true, "", s: Noise.generate_keypair(protocol))
      server = Noise.handshake(protocol, false, "", s: Noise.generate_keypair(protocol))
      {:ok, m1, client} = Noise.handshake_step(client, "")
      {:ok, "", server} = Noise.handshake_step(server, m1)
      {:ok, m2, server} = Noise.handshake_step(server, "")
      {:ok, protocol: protocol, client: client, server: server, m1: m1, m2: m2}
    end

    test "truncated ephemeral is malformed", %{protocol: protocol} do
      server = Noise.handshake(protocol, false, "", s: Noise.generate_keypair(protocol))
      assert {:error, :malformed_message} = Noise.handshake_step(server, <<1, 2, 3>>)
      assert {:error, :malformed_message} = Noise.handshake_step(server, <<>>)
    end

    test "truncated encrypted static and payload are malformed", %{client: client, m2: m2} do
      # m2 = e(32) || enc(s)(48) || enc(payload)(16)
      assert {:error, :malformed_message} = Noise.handshake_step(client, binary_part(m2, 0, 40))
      assert {:error, :malformed_message} = Noise.handshake_step(client, binary_part(m2, 0, 90))
    end

    test "flipped tag bit fails authentication", %{client: client, m2: m2} do
      size = byte_size(m2) - 1
      <<prefix::binary-size(^size), last>> = m2
      tampered = <<prefix::binary, Bitwise.bxor(last, 1)>>

      assert {:error, :decrypt_failed} = Noise.handshake_step(client, tampered)
    end

    test "low-order ephemeral is rejected as invalid_public_key", %{protocol: protocol} do
      server = Noise.handshake(protocol, false, "", s: Noise.generate_keypair(protocol))
      {:ok, "", server} = Noise.handshake_step(server, <<0::256>>)
      # the DH happens on the responder's write (ee)
      assert {:error, :invalid_public_key} = Noise.handshake_step(server, "")
    end

    test "messages over 65535 bytes are rejected on read and write", %{client: client, m2: m2} do
      assert {:error, :message_too_long} =
               Noise.handshake_step(client, m2 <> :binary.copy(<<0>>, 65_536))

      {:ok, "", client} = Noise.handshake_step(client, m2)

      assert {:error, :message_too_long} =
               Noise.handshake_step(client, :binary.copy(<<0>>, 65_500))

      assert {:complete, _, _} =
               Noise.handshake_step(client, :binary.copy(<<0>>, 65_535 - 48 - 16))
    end
  end

  describe "transport" do
    test "decrypt failure keeps the receive state in sync" do
      {client, server, _, _} = complete_xx()
      {tx, _} = Noise.split(client)
      {_, rx} = Noise.split(server)

      {:ok, c1, tx} = Noise.encrypt(tx, "one")
      {:ok, c2, _tx} = Noise.encrypt(tx, "two")

      assert {:error, :decrypt_failed} = Noise.decrypt(rx, c2)
      {:ok, "one", rx} = Noise.decrypt(rx, c1)
      {:ok, "two", _rx} = Noise.decrypt(rx, c2)
    end

    test "message length bound" do
      {client, server, _, _} = complete_xx()
      {tx, _} = Noise.split(client)
      {_, rx} = Noise.split(server)

      assert {:ok, ciphertext, _} = Noise.encrypt(tx, :binary.copy(<<0>>, 65_519))
      assert byte_size(ciphertext) == 65_535
      assert {:ok, _, _} = Noise.decrypt(rx, ciphertext)
      assert {:error, :message_too_long} = Noise.encrypt(tx, :binary.copy(<<0>>, 65_520))
      assert {:error, :message_too_long} = Noise.decrypt(rx, <<0::size(65_536 * 8)>>)
    end

    test "nonce exhaustion is reported and survives rekey" do
      {client, server, _, _} = complete_xx()
      {tx, _} = Noise.split(client)
      {_, rx} = Noise.split(server)
      tx = Noise.CipherState.set_nonce(tx, 0xFFFF_FFFF_FFFF_FFFE)
      rx = Noise.CipherState.set_nonce(rx, 0xFFFF_FFFF_FFFF_FFFE)
      {:ok, last, tx} = Noise.encrypt(tx, "last")
      {:ok, "last", rx} = Noise.decrypt(rx, last)

      assert {:error, :nonce_exhausted} = Noise.encrypt(tx, "too many")
      assert {:error, :nonce_exhausted} = Noise.decrypt(rx, last)
      # rekey keeps the nonce (spec §11.3), so it does not revive the state
      assert {:error, :nonce_exhausted} = Noise.encrypt(Noise.rekey(tx), "too many")
      assert {:error, :nonce_exhausted} = Noise.decrypt(Noise.rekey(rx), last)
    end

    test "rekey in lockstep" do
      {client, server, _, _} = complete_xx()
      {tx, _} = Noise.split(client)
      {_, rx} = Noise.split(server)

      {:ok, c, _} = Noise.encrypt(Noise.rekey(tx), "fresh")
      assert {:error, :decrypt_failed} = Noise.decrypt(rx, c)
      assert {:ok, "fresh", _} = Noise.decrypt(Noise.rekey(rx), c)
    end

    test "keyless cipher state is refused" do
      cs = Noise.CipherState.initialize(Noise.protocol(@xx))
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
