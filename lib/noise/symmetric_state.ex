defmodule Noise.SymmetricState do
  @moduledoc """
  A `SymmetricState` (spec §5.2): chaining key `ck`, handshake hash `h` and
  an embedded `Noise.CipherState`.

  Internal to the handshake; users interact with it through
  `Noise.HandshakeState`. The chaining key is redacted from `inspect/1`.
  """

  alias Noise.CipherState
  alias Noise.Crypto.Hash
  alias Noise.Protocol

  @derive {Inspect, except: [:ck]}
  @enforce_keys [:protocol, :cipher_state, :ck, :h]
  defstruct [:protocol, :ck, :h, :cipher_state]

  @opaque t() :: %__MODULE__{
            protocol: Protocol.t(),
            ck: Hash.hash(),
            h: Hash.hash(),
            cipher_state: CipherState.t()
          }

  @doc "`InitializeSymmetric(protocol_name)` (spec §5.2): pad or hash the name into `h`."
  @spec initialize(Protocol.t()) :: t()
  def initialize(%Protocol{name: name, hashlen: hashlen} = protocol)
      when byte_size(name) <= hashlen do
    padding = 8 * (hashlen - byte_size(name))
    do_init(protocol, <<name::binary, 0::size(padding)>>)
  end

  def initialize(%Protocol{name: name} = protocol) do
    do_init(protocol, Protocol.hash(protocol, name))
  end

  @spec mix_key(t(), binary()) :: t()
  def mix_key(%__MODULE__{protocol: protocol, ck: ck} = state, input_key_material) do
    {ck, <<temp_k::binary-size(32), _::binary>>} =
      Protocol.hkdf(protocol, ck, input_key_material, 2)

    %__MODULE__{
      state
      | ck: ck,
        cipher_state: CipherState.initialize_key(state.cipher_state, temp_k)
    }
  end

  @spec mix_hash(t(), iodata()) :: t()
  def mix_hash(%__MODULE__{protocol: protocol, h: h} = state, data) do
    %__MODULE__{state | h: Protocol.hash(protocol, [h, data])}
  end

  @spec mix_key_and_hash(t(), binary()) :: t()
  def mix_key_and_hash(%__MODULE__{protocol: protocol, ck: ck} = state, input_key_material) do
    {ck, temp_h, <<temp_k::binary-size(32), _::binary>>} =
      Protocol.hkdf(protocol, ck, input_key_material, 3)

    %__MODULE__{state | ck: ck}
    |> mix_hash(temp_h)
    |> Map.update!(:cipher_state, &CipherState.initialize_key(&1, temp_k))
  end

  @spec handshake_hash(t()) :: Hash.hash()
  def handshake_hash(%__MODULE__{h: h}), do: h

  @spec has_key?(t()) :: boolean()
  def has_key?(%__MODULE__{cipher_state: cs}), do: CipherState.has_key?(cs)

  @spec encrypt_and_hash(t(), binary()) :: {:ok, binary(), t()} | {:error, :nonce_exhausted}
  def encrypt_and_hash(%__MODULE__{cipher_state: cs, h: h} = state, plain_text) do
    with {:ok, cipher_text, cs} <- CipherState.encrypt_with_ad(cs, h, plain_text) do
      {:ok, cipher_text, mix_hash(%__MODULE__{state | cipher_state: cs}, cipher_text)}
    end
  end

  @spec decrypt_and_hash(t(), binary()) :: {:ok, binary(), t()} | {:error, CipherState.error()}
  def decrypt_and_hash(%__MODULE__{cipher_state: cs, h: h} = state, cipher_text) do
    with {:ok, plain_text, cs} <- CipherState.decrypt_with_ad(cs, h, cipher_text) do
      {:ok, plain_text, mix_hash(%__MODULE__{state | cipher_state: cs}, cipher_text)}
    end
  end

  @doc "`Split()` (spec §5.2): `{c1, c2}` where `c1` is initiator→responder."
  @spec split(t()) :: {CipherState.t(), CipherState.t()}
  def split(%__MODULE__{protocol: protocol, ck: ck}) do
    {<<temp_k1::binary-size(32), _::binary>>, <<temp_k2::binary-size(32), _::binary>>} =
      Protocol.hkdf(protocol, ck, <<>>, 2)

    {
      CipherState.initialize_key(CipherState.initialize(protocol), temp_k1),
      CipherState.initialize_key(CipherState.initialize(protocol), temp_k2)
    }
  end

  defp do_init(protocol, h) do
    %__MODULE__{protocol: protocol, cipher_state: CipherState.initialize(protocol), h: h, ck: h}
  end
end
