defmodule Noise.HostileInputTest do
  use ExUnit.Case, async: true

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
    protocol = Noise.protocol(name)
    {_, init_pub} = init_s = Noise.generate_keypair(protocol)
    {_, resp_pub} = resp_s = Noise.generate_keypair(protocol)
    psks = List.duplicate(@psk, Noise.Pattern.psk_count(protocol.pattern))

    init_opts = [psks: psks] ++ Keyword.take([s: init_s, rs: resp_pub], init_keys)
    resp_opts = [psks: psks] ++ Keyword.take([s: resp_s, rs: init_pub], resp_keys)

    {Noise.handshake(protocol, true, "", init_opts),
     Noise.handshake(protocol, false, "", resp_opts)}
  end

  # Completes the handshake and returns, for every message, the sender's state
  # after writing it, the receiver's state before reading it, and the message.
  # Unauthenticated messages carry an empty payload so that any truncation
  # cuts into their tokens.
  defp transcript(sender, receiver, cleartext, index \\ 0) do
    cleartext? = index in cleartext
    payload = if cleartext?, do: "", else: "payload"
    {status, message, sender_after} = Noise.handshake_step(sender, payload)
    {^status, ^payload, receiver_after} = Noise.handshake_step(receiver, message)
    entry = %{cleartext?: cleartext?, sender: sender_after, receiver: receiver, message: message}

    case status do
      :complete -> [entry]
      :ok -> [entry | transcript(receiver_after, sender_after, cleartext, index + 1)]
    end
  end

  for {name, init_keys, resp_keys, cleartext} <- @cases do
    test "#{name}: every truncated handshake message is malformed or fails authentication" do
      {init, resp} = pair(unquote(name), unquote(init_keys), unquote(resp_keys))

      for %{receiver: receiver, message: message} <- transcript(init, resp, unquote(cleartext)),
          length <- 0..(byte_size(message) - 1) do
        assert {:error, reason} = Noise.handshake_step(receiver, binary_part(message, 0, length))
        assert reason in [:malformed_message, :decrypt_failed]
      end
    end

    test "#{name}: a flipped bit is rejected by the first authenticated message covering it" do
      {init, resp} = pair(unquote(name), unquote(init_keys), unquote(resp_keys))

      for %{cleartext?: cleartext?, sender: sender, receiver: receiver, message: message} <-
            transcript(init, resp, unquote(cleartext)),
          offset <- 0..(byte_size(message) - 1) do
        <<prefix::binary-size(^offset), byte, suffix::binary>> = message
        tampered = <<prefix::binary, Bitwise.bxor(byte, 1), suffix::binary>>

        if cleartext? do
          # nothing authenticates this message yet, so the read succeeds, but
          # the receiver's reply no longer decrypts at the original sender
          assert {:ok, "", receiver} = Noise.handshake_step(receiver, tampered)
          {:ok, reply, _} = Noise.handshake_step(receiver, "payload")
          assert {:error, :decrypt_failed} = Noise.handshake_step(sender, reply)
        else
          assert {:error, _} = Noise.handshake_step(receiver, tampered)
        end
      end
    end
  end

  describe "mismatched configuration" do
    test "different PSKs fail at the first message the PSK authenticates" do
      # NNpsk0: the PSK is mixed before the first payload is encrypted
      init = Noise.handshake("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s", true, "", psks: [@psk])

      resp =
        Noise.handshake("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s", false, "", psks: [<<1::256>>])

      {:ok, m1, _} = Noise.handshake_step(init, "")
      assert {:error, :decrypt_failed} = Noise.handshake_step(resp, m1)

      # XXpsk3: the PSK only enters with the third message
      protocol = Noise.protocol("Noise_XXpsk3_25519_AESGCM_SHA256")

      init =
        Noise.handshake(protocol, true, "", s: Noise.generate_keypair(protocol), psks: [@psk])

      resp =
        Noise.handshake(protocol, false, "",
          s: Noise.generate_keypair(protocol),
          psks: [<<1::256>>]
        )

      {:ok, m1, init} = Noise.handshake_step(init, "")
      {:ok, "", resp} = Noise.handshake_step(resp, m1)
      {:ok, m2, resp} = Noise.handshake_step(resp, "")
      {:ok, "", init} = Noise.handshake_step(init, m2)
      {:complete, m3, _} = Noise.handshake_step(init, "")
      assert {:error, :decrypt_failed} = Noise.handshake_step(resp, m3)
    end

    test "different prologues fail at the first authenticated message" do
      init = Noise.handshake("Noise_NN_25519_ChaChaPoly_BLAKE2s", true, "client view")
      resp = Noise.handshake("Noise_NN_25519_ChaChaPoly_BLAKE2s", false, "server view")

      # -> e carries no key, so the mismatch surfaces on <- e, ee
      {:ok, m1, init} = Noise.handshake_step(init, "")
      {:ok, "", resp} = Noise.handshake_step(resp, m1)
      {:complete, m2, _} = Noise.handshake_step(resp, "")
      assert {:error, :decrypt_failed} = Noise.handshake_step(init, m2)
    end
  end

  test "X448 low-order points are rejected as invalid_public_key during a handshake" do
    protocol = Noise.protocol("Noise_NK_448_ChaChaPoly_BLAKE2b")
    {_, resp_pub} = resp_s = Noise.generate_keypair(protocol)
    resp = Noise.handshake(protocol, false, "", s: resp_s)

    for u <- [0, 1, @x448_p - 1] do
      point = <<u::little-size(448)>>

      # NK: -> e, es -- the responder computes DH(s, re) while reading
      assert {:error, :invalid_public_key} =
               Noise.handshake_step(resp, point <> :binary.copy(<<0>>, 16))

      # a low-order pre-shared static key fails on the initiator's first write
      init = Noise.handshake(protocol, true, "", rs: point)
      assert {:error, :invalid_public_key} = Noise.handshake_step(init, "")
    end

    # the same handshake with a genuine key succeeds
    init = Noise.handshake(protocol, true, "", rs: resp_pub)
    {:ok, m1, _} = Noise.handshake_step(init, "")
    assert {:ok, "", _} = Noise.handshake_step(resp, m1)
  end
end
