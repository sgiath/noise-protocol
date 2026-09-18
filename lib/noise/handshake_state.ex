defmodule Noise.HandshakeState do
  @moduledoc """
  A `HandshakeState` (spec §5.3): the symmetric state plus the local and
  remote key material and the message patterns still to process.

  `write_message/2` and `read_message/2` are the spec's `WriteMessage` and
  `ReadMessage`. Both enforce whose turn it is, the 65535-byte message bound
  (spec §3) and return `{:error, reason}` instead of crashing on hostile
  input. Configuration mistakes (missing keys, wrong PSK count) raise
  `ArgumentError` from `initialize/4`.

  Private keys and PSKs are redacted from `inspect/1` output.
  """

  alias Noise.CipherState
  alias Noise.Crypto.DH
  alias Noise.Pattern
  alias Noise.Protocol
  alias Noise.SymmetricState

  @max_message_length 65_535

  @derive {Inspect, except: [:s, :e, :psks]}
  @enforce_keys [:protocol, :initiator, :symmetric_state, :message_patterns]
  defstruct [
    :protocol,
    :initiator,
    :symmetric_state,
    :message_patterns,
    :s,
    :e,
    :rs,
    :re,
    psks: []
  ]

  @opaque t() :: %__MODULE__{
            protocol: Protocol.t(),
            initiator: boolean(),
            symmetric_state: SymmetricState.t(),
            message_patterns: [{Pattern.role(), [Pattern.token()]}],
            s: DH.keypair() | nil,
            e: DH.keypair() | nil,
            rs: DH.pubkey() | nil,
            re: DH.pubkey() | nil,
            psks: [binary()]
          }

  @type error() ::
          :decrypt_failed
          | :nonce_exhausted
          | :malformed_message
          | :message_too_long
          | :invalid_public_key
          | :wrong_turn
          | :handshake_complete

  @type option ::
          {:s, DH.keypair()}
          | {:rs, DH.pubkey()}
          | {:e, DH.keypair()}
          | {:re, DH.pubkey()}
          | {:psks, [<<_::256>>]}

  @doc """
  `Initialize(handshake_pattern, initiator, prologue, s, e, rs, re)` (spec §5.3).

  Options:

    * `:s` - local static keypair `{private, public}`; required when the
      pattern transmits or pre-shares this party's static key
    * `:rs` - remote static public key; required when the pattern pre-shares
      the peer's static key, forbidden when the peer transmits it
    * `:psks` - list of 32-byte pre-shared keys, one per `psk` token
    * `:e` - local ephemeral keypair, **for test vectors only**; reusing an
      ephemeral across handshakes is catastrophic (spec §14)
    * `:re` - remote ephemeral public key; only meaningful for patterns that
      pre-share it
  """
  @spec initialize(Protocol.t() | String.t(), boolean(), binary(), [option()]) :: t()
  def initialize(protocol, initiator, prologue \\ <<>>, opts \\ [])

  def initialize(protocol_name, initiator, prologue, opts) when is_binary(protocol_name) do
    protocol_name
    |> Protocol.from_name()
    |> initialize(initiator, prologue, opts)
  end

  def initialize(%Protocol{pattern: pattern} = protocol, initiator, prologue, opts)
      when is_boolean(initiator) and is_binary(prologue) do
    opts = Keyword.validate!(opts, s: nil, rs: nil, e: nil, re: nil, psks: [])
    validate_keys!(protocol, initiator, opts)

    state = %__MODULE__{
      protocol: protocol,
      initiator: initiator,
      symmetric_state:
        protocol |> SymmetricState.initialize() |> SymmetricState.mix_hash(prologue),
      message_patterns: pattern.tokens,
      s: opts[:s],
      e: opts[:e],
      rs: opts[:rs],
      re: opts[:re],
      psks: opts[:psks]
    }

    [ini_pre, resp_pre] = pattern.pre_message

    {ini_keys, resp_keys} =
      if initiator,
        do: {local_pubs(state), remote_pubs(state)},
        else: {remote_pubs(state), local_pubs(state)}

    state
    |> mix_pre_message(ini_pre, ini_keys)
    |> mix_pre_message(resp_pre, resp_keys)
  end

  @spec initiator?(t()) :: boolean()
  def initiator?(%__MODULE__{initiator: initiator}), do: initiator

  @spec complete?(t()) :: boolean()
  def complete?(%__MODULE__{message_patterns: patterns}), do: patterns == []

  @doc "What this party must do next: send a message, receive one, or `split/1`."
  @spec next_action(t()) :: :write | :read | :split
  def next_action(%__MODULE__{message_patterns: []}), do: :split
  def next_action(%__MODULE__{initiator: true, message_patterns: [{:ini, _} | _]}), do: :write
  def next_action(%__MODULE__{initiator: false, message_patterns: [{:resp, _} | _]}), do: :write
  def next_action(%__MODULE__{}), do: :read

  @doc "`GetHandshakeHash()` (spec §5.2); for channel binding (spec §11.2) once complete."
  @spec handshake_hash(t()) :: binary()
  def handshake_hash(%__MODULE__{symmetric_state: ss}), do: SymmetricState.handshake_hash(ss)

  @doc "The remote static public key, once it is known."
  @spec remote_static(t()) :: DH.pubkey() | nil
  def remote_static(%__MODULE__{rs: rs}), do: rs

  @doc "`WriteMessage(payload)` (spec §5.3). Returns the message to send to the peer."
  @spec write_message(t(), binary()) :: {:ok, binary(), t()} | {:error, error()}
  def write_message(%__MODULE__{message_patterns: []}, _payload),
    do: {:error, :handshake_complete}

  def write_message(%__MODULE__{message_patterns: [{_, tokens} | rest]} = state, payload)
      when is_binary(payload) do
    with :write <- next_action(state),
         {:ok, prefix, state} <-
           write_tokens(%__MODULE__{state | message_patterns: rest}, tokens, <<>>),
         {:ok, cipher_text, state} <- encrypt_and_hash(state, payload),
         message = <<prefix::binary, cipher_text::binary>>,
         true <- byte_size(message) <= @max_message_length do
      {:ok, message, state}
    else
      :read -> {:error, :wrong_turn}
      false -> {:error, :message_too_long}
      {:error, _} = error -> error
    end
  end

  @doc "`ReadMessage(message)` (spec §5.3). Returns the decrypted payload."
  @spec read_message(t(), binary()) :: {:ok, binary(), t()} | {:error, error()}
  def read_message(%__MODULE__{message_patterns: []}, _message), do: {:error, :handshake_complete}

  def read_message(%__MODULE__{}, message) when byte_size(message) > @max_message_length do
    {:error, :message_too_long}
  end

  def read_message(%__MODULE__{message_patterns: [{_, tokens} | rest]} = state, message)
      when is_binary(message) do
    with :read <- next_action(state),
         {:ok, rest_message, state} <-
           read_tokens(%__MODULE__{state | message_patterns: rest}, tokens, message),
         true <- not has_key?(state) or byte_size(rest_message) >= 16,
         {:ok, payload, state} <- decrypt_and_hash(state, rest_message) do
      {:ok, payload, state}
    else
      :write -> {:error, :wrong_turn}
      false -> {:error, :malformed_message}
      {:error, _} = error -> error
    end
  end

  @doc """
  `Split()` (spec §5.2): `{c1, c2}` where `c1` encrypts initiator→responder
  and `c2` responder→initiator. Raises unless the handshake is complete.
  """
  @spec split(t()) :: {CipherState.t(), CipherState.t()}
  def split(%__MODULE__{message_patterns: [], symmetric_state: ss}), do: SymmetricState.split(ss)

  def split(%__MODULE__{}) do
    raise ArgumentError, "cannot split: handshake is not complete"
  end

  # --- initialization ------------------------------------------------------

  defp validate_keys!(%Protocol{pattern: pattern, dhlen: dhlen}, initiator, opts) do
    {me, peer} = if initiator, do: {:ini, :resp}, else: {:resp, :ini}

    validate_static!(pattern, me, opts[:s])
    validate_remote_static!(pattern, peer, opts[:rs])
    validate_remote_ephemeral!(pattern, peer, opts[:re])
    validate_psks!(pattern, opts[:psks])

    validate_keypair!(opts[:s], :s, dhlen)
    validate_keypair!(opts[:e], :e, dhlen)
    validate_pubkey!(opts[:rs], :rs, dhlen)
    validate_pubkey!(opts[:re], :re, dhlen)
  end

  defp validate_static!(pattern, me, nil) do
    if Pattern.transmits?(pattern, me, :s) or Pattern.pre_shares?(pattern, me, :s) do
      raise ArgumentError, "pattern #{pattern.name} requires the local static keypair (:s)"
    end
  end

  defp validate_static!(_pattern, _me, _s), do: :ok

  defp validate_remote_static!(pattern, peer, nil) do
    if Pattern.pre_shares?(pattern, peer, :s) do
      raise ArgumentError, "pattern #{pattern.name} requires the remote static public key (:rs)"
    end
  end

  defp validate_remote_static!(pattern, peer, _rs) do
    if Pattern.transmits?(pattern, peer, :s) do
      raise ArgumentError,
            "pattern #{pattern.name} transmits the remote static key; :rs must not be set"
    end
  end

  defp validate_remote_ephemeral!(_pattern, _peer, nil), do: :ok

  defp validate_remote_ephemeral!(pattern, peer, _re) do
    if Pattern.transmits?(pattern, peer, :e) do
      raise ArgumentError,
            "pattern #{pattern.name} transmits the remote ephemeral key; :re must not be set"
    end
  end

  defp validate_psks!(pattern, psks) do
    expected = Pattern.psk_count(pattern)

    if length(psks) != expected do
      raise ArgumentError,
            "pattern #{pattern.name} needs #{expected} pre-shared key(s), got #{length(psks)}"
    end

    if not Enum.all?(psks, &(is_binary(&1) and byte_size(&1) == 32)) do
      raise ArgumentError, "pre-shared keys must be 32 bytes (spec §9.2)"
    end
  end

  defp validate_keypair!(nil, _name, _dhlen), do: :ok

  defp validate_keypair!({sec, pub}, _name, dhlen)
       when is_binary(sec) and is_binary(pub) and byte_size(pub) == dhlen,
       do: :ok

  defp validate_keypair!(_other, name, dhlen) do
    raise ArgumentError,
          "#{name} must be a {private_key, public_key} tuple with a #{dhlen}-byte public key"
  end

  defp validate_pubkey!(nil, _name, _dhlen), do: :ok

  defp validate_pubkey!(pub, _name, dhlen) when is_binary(pub) and byte_size(pub) == dhlen,
    do: :ok

  defp validate_pubkey!(_other, name, dhlen) do
    raise ArgumentError, "#{name} must be a #{dhlen}-byte public key"
  end

  defp local_pubs(%__MODULE__{e: e, s: s}), do: {pub(e), pub(s)}
  defp remote_pubs(%__MODULE__{re: re, rs: rs}), do: {re, rs}

  defp pub({_sec, pub}), do: pub
  defp pub(nil), do: nil

  # Pre-messages (spec §7.1): only `e`, `s` and `e, s` are valid
  defp mix_pre_message(state, [], _keys), do: state
  defp mix_pre_message(state, [:s], {_e, s}), do: mix_hash(state, s)
  defp mix_pre_message(state, [:e], {e, _s}), do: mix_ephemeral(state, e)
  defp mix_pre_message(state, [:e, :s], {e, s}), do: state |> mix_ephemeral(e) |> mix_hash(s)

  # --- tokens ---------------------------------------------------------------

  defp write_tokens(state, [], message), do: {:ok, message, state}

  defp write_tokens(state, [token | rest], message) do
    with {:ok, message, state} <- write_token(state, token, message) do
      write_tokens(state, rest, message)
    end
  end

  defp write_token(%__MODULE__{e: nil} = state, :e, message) do
    write_token(%__MODULE__{state | e: Protocol.generate_keypair(state.protocol)}, :e, message)
  end

  defp write_token(%__MODULE__{e: {_sec, pub}} = state, :e, message) do
    {:ok, <<message::binary, pub::binary>>, mix_ephemeral(state, pub)}
  end

  defp write_token(%__MODULE__{s: {_sec, pub}} = state, :s, message) do
    with {:ok, cipher_text, state} <- encrypt_and_hash(state, pub) do
      {:ok, <<message::binary, cipher_text::binary>>, state}
    end
  end

  defp write_token(state, token, message) do
    with {:ok, state} <- mix_dh(state, token), do: {:ok, message, state}
  end

  defp read_tokens(state, [], message), do: {:ok, message, state}

  defp read_tokens(state, [token | rest], message) do
    with {:ok, message, state} <- read_token(state, token, message) do
      read_tokens(state, rest, message)
    end
  end

  defp read_token(%__MODULE__{protocol: %Protocol{dhlen: dhlen}} = state, :e, message) do
    case message do
      <<re::binary-size(^dhlen), rest::binary>> ->
        {:ok, rest, mix_ephemeral(%__MODULE__{state | re: re}, re)}

      _ ->
        {:error, :malformed_message}
    end
  end

  defp read_token(%__MODULE__{protocol: %Protocol{dhlen: dhlen}} = state, :s, message) do
    len = if has_key?(state), do: dhlen + 16, else: dhlen

    with <<temp::binary-size(^len), rest::binary>> <- message,
         {:ok, rs, state} <- decrypt_and_hash(state, temp) do
      {:ok, rest, %__MODULE__{state | rs: rs}}
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed_message}
    end
  end

  defp read_token(state, token, message) do
    with {:ok, state} <- mix_dh(state, token), do: {:ok, message, state}
  end

  # In PSK handshakes the ephemeral is also mixed into the key (spec §9.2)
  defp mix_ephemeral(state, pub) do
    state = mix_hash(state, pub)
    if Pattern.psk?(state.protocol.pattern), do: mix_key(state, pub), else: state
  end

  defp mix_dh(%__MODULE__{e: e, re: re} = state, :ee), do: dh(state, e, re)
  defp mix_dh(%__MODULE__{initiator: true, e: e, rs: rs} = state, :es), do: dh(state, e, rs)
  defp mix_dh(%__MODULE__{initiator: false, s: s, re: re} = state, :es), do: dh(state, s, re)
  defp mix_dh(%__MODULE__{initiator: true, s: s, re: re} = state, :se), do: dh(state, s, re)
  defp mix_dh(%__MODULE__{initiator: false, e: e, rs: rs} = state, :se), do: dh(state, e, rs)
  defp mix_dh(%__MODULE__{s: s, rs: rs} = state, :ss), do: dh(state, s, rs)

  defp mix_dh(%__MODULE__{psks: [psk | psks]} = state, :psk) do
    {:ok, mix_key_and_hash(%__MODULE__{state | psks: psks}, psk)}
  end

  defp dh(state, keypair, pubkey) do
    with {:ok, shared_secret} <- Protocol.dh(state.protocol, keypair, pubkey) do
      {:ok, mix_key(state, shared_secret)}
    end
  end

  # --- symmetric state delegation -------------------------------------------

  defp has_key?(%__MODULE__{symmetric_state: ss}), do: SymmetricState.has_key?(ss)

  defp mix_key(%__MODULE__{symmetric_state: ss} = state, ikm) do
    %__MODULE__{state | symmetric_state: SymmetricState.mix_key(ss, ikm)}
  end

  defp mix_hash(%__MODULE__{symmetric_state: ss} = state, data) do
    %__MODULE__{state | symmetric_state: SymmetricState.mix_hash(ss, data)}
  end

  defp mix_key_and_hash(%__MODULE__{symmetric_state: ss} = state, ikm) do
    %__MODULE__{state | symmetric_state: SymmetricState.mix_key_and_hash(ss, ikm)}
  end

  defp encrypt_and_hash(%__MODULE__{symmetric_state: ss} = state, plain_text) do
    with {:ok, cipher_text, ss} <- SymmetricState.encrypt_and_hash(ss, plain_text) do
      {:ok, cipher_text, %__MODULE__{state | symmetric_state: ss}}
    end
  end

  defp decrypt_and_hash(%__MODULE__{symmetric_state: ss} = state, cipher_text) do
    with {:ok, plain_text, ss} <- SymmetricState.decrypt_and_hash(ss, cipher_text) do
      {:ok, plain_text, %__MODULE__{state | symmetric_state: ss}}
    end
  end
end
