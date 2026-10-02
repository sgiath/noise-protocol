defmodule Noise.CipherState do
  @moduledoc """
  A `CipherState` (spec §5.1): a 32-byte key `k` and a 64-bit nonce `n`.

  Produced in pairs by `Noise.split/1` once a handshake completes; used for
  transport messages through `Noise.encrypt/3` and `Noise.decrypt/3`.

  Spec rules enforced here:

    * `n` is never incremented on a failed decryption.
    * Once `n` reaches `2^64-1` (reserved for `rekey/1`) every further
      encrypt/decrypt returns `{:error, :nonce_exhausted}`.

  The key is redacted from `inspect/1` output.
  """

  alias Noise.Crypto.Cipher
  alias Noise.Protocol

  @derive {Inspect, except: [:k]}
  @enforce_keys [:protocol]
  defstruct protocol: nil, k: nil, n: 0

  @opaque t() :: %__MODULE__{
            protocol: Protocol.t(),
            k: Cipher.key() | nil,
            n: Cipher.nonce()
          }

  @type error() :: :decrypt_failed | :nonce_exhausted

  @max_nonce Cipher.max_nonce()

  defguardp is_key(k) when is_binary(k) and byte_size(k) == 32
  defguardp is_nonce(n) when is_integer(n) and n >= 0 and n < @max_nonce

  @doc "A `CipherState` without a key; encrypt/decrypt pass data through unchanged (spec §5.1)."
  @spec initialize(Protocol.t()) :: t()
  def initialize(%Protocol{} = protocol), do: %__MODULE__{protocol: protocol}

  @doc "Sets a 32-byte key and resets the nonce to 0."
  @spec initialize_key(t(), Cipher.key()) :: t()
  def initialize_key(%__MODULE__{} = state, key) when is_key(key) do
    %__MODULE__{state | k: key, n: 0}
  end

  @spec has_key?(t()) :: boolean()
  def has_key?(%__MODULE__{k: key}) when is_key(key), do: true
  def has_key?(%__MODULE__{}), do: false

  @spec nonce(t()) :: non_neg_integer()
  def nonce(%__MODULE__{n: n}), do: n

  @doc """
  Sets the nonce explicitly (spec §11.4, out-of-order transport messages).

  Meant for **receive** states only, when the sender transmits each
  message's nonce alongside the ciphertext (e.g. over UDP). A cipher state
  does not remember which nonces it has already accepted, so with explicit
  nonces a replayed packet decrypts successfully again. The receiver must
  keep its own record (e.g. a sliding window) of nonces that decrypted
  successfully, reject any packet whose nonce is in it, and add a nonce
  only after its decryption succeeds (spec §11.4).

  Never move a **send** state's nonce backwards: encrypting two messages
  under the same key and nonce breaks the cipher.

  Raises `ArgumentError` for values outside `0..2^64-2`.
  """
  @spec set_nonce(t(), non_neg_integer()) :: t()
  def set_nonce(%__MODULE__{} = state, n) when is_nonce(n), do: %__MODULE__{state | n: n}

  def set_nonce(%__MODULE__{}, n) do
    raise ArgumentError, "nonce must be an integer in 0..2^64-2, got: #{inspect(n)}"
  end

  @doc "`ENCRYPT(k, n, ad, plaintext)` then `n++` (spec §5.1)."
  @spec encrypt_with_ad(t(), binary(), binary()) ::
          {:ok, binary(), t()} | {:error, :nonce_exhausted}
  def encrypt_with_ad(%__MODULE__{k: k, n: n} = state, ad, plain_text)
      when is_key(k) and is_nonce(n) do
    {:ok, Protocol.encrypt(state.protocol, k, n, ad, plain_text), %__MODULE__{state | n: n + 1}}
  end

  def encrypt_with_ad(%__MODULE__{k: k}, _ad, _plain_text) when is_key(k) do
    {:error, :nonce_exhausted}
  end

  def encrypt_with_ad(%__MODULE__{} = state, _ad, plain_text), do: {:ok, plain_text, state}

  @doc "`DECRYPT(k, n, ad, ciphertext)` then `n++`; `n` is unchanged on failure (spec §5.1)."
  @spec decrypt_with_ad(t(), binary(), binary()) :: {:ok, binary(), t()} | {:error, error()}
  def decrypt_with_ad(%__MODULE__{k: k, n: n} = state, ad, cipher_text)
      when is_key(k) and is_nonce(n) do
    case Protocol.decrypt(state.protocol, k, n, ad, cipher_text) do
      plain_text when is_binary(plain_text) -> {:ok, plain_text, %__MODULE__{state | n: n + 1}}
      :error -> {:error, :decrypt_failed}
    end
  end

  def decrypt_with_ad(%__MODULE__{k: k}, _ad, _cipher_text) when is_key(k) do
    {:error, :nonce_exhausted}
  end

  def decrypt_with_ad(%__MODULE__{} = state, _ad, cipher_text), do: {:ok, cipher_text, state}

  @doc "`REKEY(k)` (spec §4.2 / §11.3). The nonce is not reset."
  @spec rekey(t()) :: t()
  def rekey(%__MODULE__{k: k} = state) when is_key(k) do
    %__MODULE__{state | k: Protocol.rekey(state.protocol, k)}
  end
end
