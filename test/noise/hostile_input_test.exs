defmodule Noise.HostileInputTest do
  use ExUnit.Case, async: true

  alias Noise.HandshakeState
  alias Noise.Protocol

  @psk :binary.copy(<<0x5A>>, 32)
  @x448_p Integer.pow(2, 448) - Integer.pow(2, 224) - 1

  # {protocol, initiator keys, responder keys, unauthenticated message indexes}
  #
  # A message is unauthenticated when no cipher key exists yet when it is
  # processed (spec §5.3): its tokens and payload travel in the clear and a
  # tampered copy is accepted. Tampering must then break the next message.
  @cases [
    {"Noise_N_25519_ChaChaPoly_BLAKE2s", [:rs], [:s], []},
    {"Noise_X_25519_AESGCM_SHA256", [:s, :rs], [:s], []},
    {"Noise_X1X1_25519_ChaChaPoly_SHA512", [:s], [:s], [0]},
    {"Noise_IK_448_AESGCM_BLAKE2b", [:s, :rs], [:s], []},
    # in PSK handshakes the first `e` is mixed into the key (spec §9.2)
    {"Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s", [:s], [:s], []}
  ]

  defp pair(name, init_keys, resp_keys) do
    protocol = Protocol.from_name(name)
    {_, init_pub} = init_s = Protocol.generate_keypair(protocol)
    {_, resp_pub} = resp_s = Protocol.generate_keypair(protocol)
    psks = List.duplicate(@psk, Noise.Pattern.psk_count(protocol.pattern))

    init_opts = [psks: psks] ++ Keyword.take([s: init_s, rs: resp_pub], init_keys)
    resp_opts = [psks: psks] ++ Keyword.take([s: resp_s, rs: init_pub], resp_keys)

    {HandshakeState.initialize(protocol, true, "", init_opts),
     HandshakeState.initialize(protocol, false, "", resp_opts)}
  end

  # Completes the handshake and returns, for every message, the sender's state
  # after writing it, the receiver's state before reading it, and the message.
  # Unauthenticated messages carry an empty payload so that any truncation
  # cuts into their tokens.
  defp transcript(sender, receiver, cleartext, index \\ 0) do
    cleartext? = index in cleartext
    payload = if cleartext?, do: "", else: "payload"
    {:ok, message, sender_after} = HandshakeState.write_message(sender, payload)
    {:ok, ^payload, receiver_after} = HandshakeState.read_message(receiver, message)
    entry = %{cleartext?: cleartext?, sender: sender_after, receiver: receiver, message: message}

    if HandshakeState.complete?(receiver_after),
      do: [entry],
      else: [entry | transcript(receiver_after, sender_after, cleartext, index + 1)]
  end

  for {name, init_keys, resp_keys, cleartext} <- @cases do
    test "#{name}: every truncated handshake message is malformed or fails authentication" do
      {init, resp} = pair(unquote(name), unquote(init_keys), unquote(resp_keys))

      for %{receiver: receiver, message: message} <- transcript(init, resp, unquote(cleartext)),
          length <- 0..(byte_size(message) - 1) do
        assert {:error, reason} =
                 HandshakeState.read_message(receiver, binary_part(message, 0, length))

        assert reason in [:malformed_message, :decrypt_failed]
      end
    end

    test "#{name}: a flipped bit fails authentication at the first authenticated message covering it" do
      {init, resp} = pair(unquote(name), unquote(init_keys), unquote(resp_keys))

      for %{cleartext?: cleartext?, sender: sender, receiver: receiver, message: message} <-
            transcript(init, resp, unquote(cleartext)),
          offset <- 0..(byte_size(message) - 1) do
        <<prefix::binary-size(^offset), byte, suffix::binary>> = message
        tampered = <<prefix::binary, Bitwise.bxor(byte, 1), suffix::binary>>

        if cleartext? do
          # nothing authenticates this message yet, so the read succeeds, but
          # the receiver's reply no longer decrypts at the original sender
          assert {:ok, "", receiver} = HandshakeState.read_message(receiver, tampered)
          {:ok, reply, _} = HandshakeState.write_message(receiver, "payload")
          assert {:error, :decrypt_failed} = HandshakeState.read_message(sender, reply)
        else
          assert {:error, :decrypt_failed} = HandshakeState.read_message(receiver, tampered)
        end
      end
    end
  end

  test "an encrypted field shorter than its tag is malformed, not a decryption failure" do
    protocol = Protocol.from_name("Noise_XX_25519_ChaChaPoly_BLAKE2s")
    init = HandshakeState.initialize(protocol, true, "", s: Protocol.generate_keypair(protocol))
    resp = HandshakeState.initialize(protocol, false, "", s: Protocol.generate_keypair(protocol))
    {:ok, m1, init} = HandshakeState.write_message(init, "")
    {:ok, "", resp} = HandshakeState.read_message(resp, m1)
    {:ok, m2, _resp} = HandshakeState.write_message(resp, "")

    # <- e, ee, s, es: e (32) || encrypted s (32 + 16) || encrypted payload (16)
    assert byte_size(m2) == 96

    assert {:error, :malformed_message} =
             HandshakeState.read_message(init, binary_part(m2, 0, 40))

    assert {:error, :malformed_message} =
             HandshakeState.read_message(init, binary_part(m2, 0, 90))
  end

  test "messages over 65535 bytes are rejected on read and write (spec §3)" do
    protocol = Protocol.from_name("Noise_XX_25519_ChaChaPoly_BLAKE2s")
    init = HandshakeState.initialize(protocol, true, "", s: Protocol.generate_keypair(protocol))
    resp = HandshakeState.initialize(protocol, false, "", s: Protocol.generate_keypair(protocol))
    {:ok, m1, init} = HandshakeState.write_message(init, "")
    {:ok, "", resp} = HandshakeState.read_message(resp, m1)
    {:ok, m2, _resp} = HandshakeState.write_message(resp, "")

    assert {:error, :message_too_long} =
             HandshakeState.read_message(init, m2 <> :binary.copy(<<0>>, 65_536))

    {:ok, "", init} = HandshakeState.read_message(init, m2)

    # -> s, se: encrypted static (32 + 16) and payload tag (16) leave 65471 bytes
    assert {:error, :message_too_long} =
             HandshakeState.write_message(init, :binary.copy(<<0>>, 65_472))

    assert {:ok, m3, _} = HandshakeState.write_message(init, :binary.copy(<<0>>, 65_471))
    assert byte_size(m3) == 65_535
  end

  describe "mismatched configuration" do
    test "different PSKs fail at the first message the PSK authenticates" do
      # NNpsk0: the PSK is mixed before the first payload is encrypted
      nn_psk0 = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
      init = HandshakeState.initialize(nn_psk0, true, "", psks: [@psk])
      resp = HandshakeState.initialize(nn_psk0, false, "", psks: [<<1::256>>])

      {:ok, m1, _} = HandshakeState.write_message(init, "")
      assert {:error, :decrypt_failed} = HandshakeState.read_message(resp, m1)

      # XXpsk3: the PSK only enters with the third message
      protocol = Protocol.from_name("Noise_XXpsk3_25519_AESGCM_SHA256")

      init =
        HandshakeState.initialize(protocol, true, "",
          s: Protocol.generate_keypair(protocol),
          psks: [@psk]
        )

      resp =
        HandshakeState.initialize(protocol, false, "",
          s: Protocol.generate_keypair(protocol),
          psks: [<<1::256>>]
        )

      {:ok, m1, init} = HandshakeState.write_message(init, "")
      {:ok, "", resp} = HandshakeState.read_message(resp, m1)
      {:ok, m2, resp} = HandshakeState.write_message(resp, "")
      {:ok, "", init} = HandshakeState.read_message(init, m2)
      {:ok, m3, _} = HandshakeState.write_message(init, "")
      assert {:error, :decrypt_failed} = HandshakeState.read_message(resp, m3)
    end

    test "different prologues fail at the first authenticated message" do
      nn = "Noise_NN_25519_ChaChaPoly_BLAKE2s"
      init = HandshakeState.initialize(nn, true, "client view")
      resp = HandshakeState.initialize(nn, false, "server view")

      # -> e carries no key, so the mismatch surfaces on <- e, ee
      {:ok, m1, init} = HandshakeState.write_message(init, "")
      {:ok, "", resp} = HandshakeState.read_message(resp, m1)
      {:ok, m2, _} = HandshakeState.write_message(resp, "")
      assert {:error, :decrypt_failed} = HandshakeState.read_message(init, m2)
    end
  end

  describe "low-order points are rejected as invalid_public_key" do
    test "X25519 ephemeral, on the responder's ee" do
      protocol = Protocol.from_name("Noise_XX_25519_ChaChaPoly_BLAKE2s")

      resp =
        HandshakeState.initialize(protocol, false, "", s: Protocol.generate_keypair(protocol))

      # -> e is unauthenticated; the DH happens on the responder's write
      {:ok, "", resp} = HandshakeState.read_message(resp, <<0::256>>)
      assert {:error, :invalid_public_key} = HandshakeState.write_message(resp, "")
    end

    test "X448 ephemeral and pre-shared static" do
      protocol = Protocol.from_name("Noise_NK_448_ChaChaPoly_BLAKE2b")
      {_, resp_pub} = resp_s = Protocol.generate_keypair(protocol)
      resp = HandshakeState.initialize(protocol, false, "", s: resp_s)

      for u <- [0, 1, @x448_p - 1] do
        point = <<u::little-size(448)>>

        # NK: -> e, es -- the responder computes DH(s, re) while reading
        assert {:error, :invalid_public_key} =
                 HandshakeState.read_message(resp, point <> :binary.copy(<<0>>, 16))

        # a low-order pre-shared static key fails on the initiator's first write
        init = HandshakeState.initialize(protocol, true, "", rs: point)
        assert {:error, :invalid_public_key} = HandshakeState.write_message(init, "")
      end

      # the same handshake with a genuine key succeeds
      init = HandshakeState.initialize(protocol, true, "", rs: resp_pub)
      {:ok, m1, _} = HandshakeState.write_message(init, "")
      assert {:ok, "", _} = HandshakeState.read_message(resp, m1)
    end
  end
end
