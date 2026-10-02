defmodule Noise.HandshakeStateTest do
  use ExUnit.Case, async: true

  alias Noise.HandshakeState

  @nn "Noise_NN_25519_ChaChaPoly_BLAKE2b"
  @psk <<0::256>>

  defp keypair, do: Noise.generate_keypair(Noise.protocol(@nn))

  describe "initialize/4" do
    test "sets role and pattern" do
      state = HandshakeState.initialize(@nn, true, "prologue")
      assert HandshakeState.initiator?(state)
      assert HandshakeState.next_action(state) == :write
      refute HandshakeState.complete?(state)

      state = HandshakeState.initialize(@nn, false, "prologue")
      refute HandshakeState.initiator?(state)
      assert HandshakeState.next_action(state) == :read
    end

    test "raises for unknown protocol" do
      assert_raise ArgumentError, fn ->
        HandshakeState.initialize("Noise_ZZ_25519_ChaChaPoly_BLAKE2b", true)
      end
    end

    test "raises for unknown options" do
      assert_raise ArgumentError, fn -> HandshakeState.initialize(@nn, true, "", psk: @psk) end
    end

    test "requires :s when the pattern transmits or pre-shares the local static key" do
      assert_raise ArgumentError, ~r/requires the local static keypair/, fn ->
        HandshakeState.initialize("Noise_XX_25519_ChaChaPoly_BLAKE2b", true)
      end

      assert_raise ArgumentError, ~r/requires the local static keypair/, fn ->
        HandshakeState.initialize("Noise_NK_25519_ChaChaPoly_BLAKE2b", false)
      end

      # NK initiator has no static key
      assert %HandshakeState{} =
               HandshakeState.initialize("Noise_NK_25519_ChaChaPoly_BLAKE2b", true, "",
                 rs: elem(keypair(), 1)
               )
    end

    test "requires :rs when the peer's static key is a pre-message, forbids it when transmitted" do
      assert_raise ArgumentError, ~r/requires the remote static public key/, fn ->
        HandshakeState.initialize("Noise_IK_25519_ChaChaPoly_BLAKE2b", true, "", s: keypair())
      end

      assert_raise ArgumentError, ~r/:rs must not be set/, fn ->
        HandshakeState.initialize("Noise_XX_25519_ChaChaPoly_BLAKE2b", true, "",
          s: keypair(),
          rs: elem(keypair(), 1)
        )
      end
    end

    test "validates key shapes against DHLEN" do
      assert_raise ArgumentError, ~r/32-byte public key/, fn ->
        HandshakeState.initialize("Noise_XX_25519_ChaChaPoly_BLAKE2b", true, "",
          s: {<<1::256>>, <<1::128>>}
        )
      end

      assert_raise ArgumentError, ~r/rs must be a 32-byte public key/, fn ->
        HandshakeState.initialize("Noise_NK_25519_ChaChaPoly_BLAKE2b", true, "", rs: "short")
      end

      assert_raise ArgumentError, ~r/s must be .* valid private key/, fn ->
        HandshakeState.initialize("Noise_XX_25519_ChaChaPoly_BLAKE2b", true, "",
          s: {<<>>, elem(keypair(), 1)}
        )
      end
    end

    test "requires exactly one 32-byte PSK per psk token (spec §9.2)" do
      assert %HandshakeState{} =
               HandshakeState.initialize("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2b", true, "",
                 psks: [@psk]
               )

      assert_raise ArgumentError, ~r/needs 1 pre-shared key/, fn ->
        HandshakeState.initialize("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2b", true)
      end

      assert_raise ArgumentError, ~r/needs 0 pre-shared key/, fn ->
        HandshakeState.initialize(@nn, true, "", psks: [@psk])
      end

      assert_raise ArgumentError, ~r/must be 32 bytes/, fn ->
        HandshakeState.initialize("Noise_NNpsk0_25519_ChaChaPoly_BLAKE2b", true, "",
          psks: ["too short"]
        )
      end
    end
  end

  describe "turn enforcement" do
    test "write on the peer's turn and read on your own turn are rejected" do
      init = HandshakeState.initialize(@nn, true)
      resp = HandshakeState.initialize(@nn, false)

      assert {:error, :wrong_turn} = HandshakeState.write_message(resp, "")
      assert {:error, :wrong_turn} = HandshakeState.read_message(init, <<0::256>>)
    end

    test "after completion both operations report handshake_complete and split works once" do
      init = HandshakeState.initialize(@nn, true)
      resp = HandshakeState.initialize(@nn, false)

      {:ok, m1, init} = HandshakeState.write_message(init, "")
      {:ok, "", resp} = HandshakeState.read_message(resp, m1)
      {:ok, m2, resp} = HandshakeState.write_message(resp, "")
      {:ok, "", init} = HandshakeState.read_message(init, m2)

      assert HandshakeState.complete?(init)
      assert HandshakeState.next_action(init) == :split
      assert {:error, :handshake_complete} = HandshakeState.write_message(init, "")
      assert {:error, :handshake_complete} = HandshakeState.read_message(init, "")
      assert {c1, c2} = HandshakeState.split(init)
      assert {^c1, ^c2} = HandshakeState.split(resp)
    end

    test "split before completion raises" do
      assert_raise ArgumentError, fn ->
        HandshakeState.split(HandshakeState.initialize(@nn, true))
      end
    end
  end

  test "inspect never shows private keys or PSKs" do
    {sec, _pub} = kp = keypair()

    state =
      HandshakeState.initialize("Noise_XXpsk3_25519_ChaChaPoly_BLAKE2b", true, "",
        s: kp,
        e: kp,
        psks: [@psk]
      )

    rendered = inspect(state, limit: :infinity)
    refute rendered =~ inspect(sec)
    refute rendered =~ "psks"
    refute rendered =~ "ck:"
  end
end
