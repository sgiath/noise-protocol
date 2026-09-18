defmodule Noise do
  @moduledoc """
  Elixir implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html)
  (revision 34).

  A protocol is named by a string such as `Noise_XX_25519_ChaChaPoly_BLAKE2s`
  which selects the handshake pattern and the DH, cipher and hash functions.

  ## Supported primitives

    * **DH**: `25519`, `448`, and `secp256k1` (BOLT-8 convention; needs the
      optional `{:lib_secp256k1, "~> 0.8"}` dependency)
    * **Cipher**: `AESGCM`, `ChaChaPoly`
    * **Hash**: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`
    * **Patterns**: every one-way, fundamental and deferred pattern from the
      spec, with `pskN` modifiers

  ## Walkthrough: `Noise_XX_25519_ChaChaPoly_BLAKE2s`

  XX is a three-message handshake where both parties transmit their static
  keys, so neither needs to know the other's key up front.

      protocol = Noise.protocol("Noise_XX_25519_ChaChaPoly_BLAKE2s")
      client_kp = Noise.generate_keypair(protocol)
      server_kp = Noise.generate_keypair(protocol)

      client = Noise.handshake(protocol, true, "prologue", s: client_kp)
      server = Noise.handshake(protocol, false, "prologue", s: server_kp)

      # -> e
      {:ok, msg1, client} = Noise.handshake_step(client, "hello")
      {:ok, "hello", server} = Noise.handshake_step(server, msg1)

      # <- e, ee, s, es
      {:ok, msg2, server} = Noise.handshake_step(server, "")
      {:ok, "", client} = Noise.handshake_step(client, msg2)

      # -> s, se   (last message: both sides report :complete)
      {:complete, msg3, client} = Noise.handshake_step(client, "")
      {:complete, "", server} = Noise.handshake_step(server, msg3)

      # Channel binding and peer identity are available from the final state
      true = Noise.handshake_hash(client) == Noise.handshake_hash(server)
      true = Noise.remote_static(server) == elem(client_kp, 1)

      # Split into transport ciphers, already ordered as {send, receive} for each role
      {client_tx, client_rx} = Noise.split(client)
      {server_tx, server_rx} = Noise.split(server)

      {:ok, ciphertext, client_tx} = Noise.encrypt(client_tx, "secret")
      {:ok, "secret", server_rx} = Noise.decrypt(server_rx, ciphertext)

  `handshake_step/2` writes when it is your turn to send and reads otherwise;
  use `write_message/2` and `read_message/2` when you want that explicit.

  ## Errors

  Hostile or corrupted network input never raises. Handshake and transport
  functions return `{:error, reason}` with one of:

    * `:decrypt_failed` - AEAD authentication failed; the state is unchanged
      and the message must be discarded
    * `:malformed_message` - a handshake message is too short for its tokens
    * `:message_too_long` - a message exceeds the 65535-byte Noise limit
    * `:invalid_public_key` - the peer sent a key the DH function rejects
    * `:nonce_exhausted` - the cipher state has sent/received 2^64-1 messages
    * `:wrong_turn` - `write_message/2` called when the peer should be
      sending, or vice versa
    * `:handshake_complete` - a handshake function called after the last
      message; call `split/1`

  Configuration mistakes (unknown protocol name, missing static key, wrong
  PSK count) raise `ArgumentError` from `protocol/1` and `handshake/4`.
  """

  alias Noise.CipherState
  alias Noise.HandshakeState
  alias Noise.Protocol

  @max_message_length 65_535
  @tag_length 16

  @typedoc "A protocol name string, e.g. `\"Noise_IK_25519_ChaChaPoly_BLAKE2s\"`"
  @type protocol_name :: String.t()

  @typedoc "A keypair `{private_key, public_key}`"
  @type keypair :: Noise.Crypto.DH.keypair()

  @type handshake_state :: HandshakeState.t()
  @type cipher_state :: CipherState.t()

  @type handshake_result ::
          {:ok, binary(), handshake_state()}
          | {:complete, binary(), handshake_state()}
          | {:error, HandshakeState.error()}

  @type transport_error :: :decrypt_failed | :nonce_exhausted | :message_too_long

  @doc "Parses a protocol name into a `Noise.Protocol`. Raises `ArgumentError` if unsupported."
  @spec protocol(protocol_name()) :: Protocol.t()
  def protocol(name), do: Protocol.from_name(name)

  @doc "Generates a fresh keypair for the protocol's DH function."
  @spec generate_keypair(Protocol.t()) :: keypair()
  def generate_keypair(%Protocol{} = protocol), do: Protocol.generate_keypair(protocol)

  @doc """
  Initializes a handshake. See `Noise.HandshakeState.initialize/4` for the
  options (`:s`, `:rs`, `:psks`, …) and which patterns require them.
  """
  @spec handshake(Protocol.t() | protocol_name(), boolean(), binary(), [HandshakeState.option()]) ::
          handshake_state()
  def handshake(protocol, initiator, prologue \\ <<>>, opts \\ []) do
    HandshakeState.initialize(protocol, initiator, prologue, opts)
  end

  @doc """
  Advances the handshake: writes a message carrying `data` as payload when it
  is this party's turn to send, otherwise reads `data` as the peer's message
  and returns its payload.

  Returns `{:complete, message_or_payload, state}` on the final message.
  """
  @spec handshake_step(handshake_state(), binary()) :: handshake_result()
  def handshake_step(state, data \\ <<>>) do
    case HandshakeState.next_action(state) do
      :write -> write_message(state, data)
      :read -> read_message(state, data)
      :split -> {:error, :handshake_complete}
    end
  end

  @doc "Writes the next handshake message with `payload`. `{:error, :wrong_turn}` if the peer should send."
  @spec write_message(handshake_state(), binary()) :: handshake_result()
  def write_message(state, payload) do
    state |> HandshakeState.write_message(payload) |> tag_completion()
  end

  @doc "Reads the peer's handshake `message` and returns its payload. `{:error, :wrong_turn}` if it is your turn to send."
  @spec read_message(handshake_state(), binary()) :: handshake_result()
  def read_message(state, message) do
    state |> HandshakeState.read_message(message) |> tag_completion()
  end

  @doc """
  Splits a completed handshake into `{send, receive}` cipher states for
  *this* party — the initiator→responder / responder→initiator ordering of
  the spec is already resolved by role. Raises unless complete.
  """
  @spec split(handshake_state()) :: {cipher_state(), cipher_state()}
  def split(state) do
    {c1, c2} = HandshakeState.split(state)
    if HandshakeState.initiator?(state), do: {c1, c2}, else: {c2, c1}
  end

  @doc "The handshake hash `h`, for channel binding (spec §11.2)."
  @spec handshake_hash(handshake_state()) :: binary()
  defdelegate handshake_hash(state), to: HandshakeState

  @doc "The peer's static public key, once received or pre-shared."
  @spec remote_static(handshake_state()) :: binary() | nil
  defdelegate remote_static(state), to: HandshakeState

  @doc """
  Encrypts a transport message. `plain_text` may be at most 65519 bytes so
  the message with its tag fits the Noise limit.
  """
  @spec encrypt(cipher_state(), binary(), binary()) ::
          {:ok, binary(), cipher_state()} | {:error, transport_error()}
  def encrypt(cipher_state, plain_text, ad \\ <<>>) do
    ensure_key!(cipher_state)

    if byte_size(plain_text) > @max_message_length - @tag_length do
      {:error, :message_too_long}
    else
      CipherState.encrypt_with_ad(cipher_state, ad, plain_text)
    end
  end

  @doc "Decrypts a transport message. On `{:error, :decrypt_failed}` the cipher state is unchanged; keep using it."
  @spec decrypt(cipher_state(), binary(), binary()) ::
          {:ok, binary(), cipher_state()} | {:error, transport_error()}
  def decrypt(cipher_state, cipher_text, ad \\ <<>>) do
    ensure_key!(cipher_state)

    if byte_size(cipher_text) > @max_message_length do
      {:error, :message_too_long}
    else
      CipherState.decrypt_with_ad(cipher_state, ad, cipher_text)
    end
  end

  @doc "Derives a new key for the cipher state (spec §11.3). Both parties must rekey in lockstep."
  @spec rekey(cipher_state()) :: cipher_state()
  defdelegate rekey(cipher_state), to: CipherState

  defp tag_completion({:ok, data, state}) do
    if HandshakeState.complete?(state), do: {:complete, data, state}, else: {:ok, data, state}
  end

  defp tag_completion({:error, _} = error), do: error

  defp ensure_key!(cipher_state) do
    if not CipherState.has_key?(cipher_state) do
      raise ArgumentError, "cipher state has no key; use the states returned by Noise.split/1"
    end
  end
end
