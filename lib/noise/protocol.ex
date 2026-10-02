defmodule Noise.Protocol do
  @moduledoc """
  A parsed Noise protocol name (spec §8): handshake pattern plus the DH,
  cipher and hash functions it names, resolved to implementation modules.

  Build one with `Noise.protocol/1`. Supported components:

    * DH: `25519`, `448`, `secp256k1` (needs the optional `lib_secp256k1` dep)
    * Cipher: `AESGCM`, `ChaChaPoly`
    * Hash: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b`

  ## Custom primitives

  `from_name/1` only knows the primitives above, but every operation
  dispatches through the module fields of this struct, so another
  implementation of `Noise.Crypto.DH`, `Noise.Crypto.Cipher` or
  `Noise.Crypto.Hash` can be plugged in by building the struct yourself.
  Start from a parsed built-in name and replace the component:

      base = Noise.protocol("Noise_XX_25519_ChaChaPoly_SHA256")

      protocol = %Noise.Protocol{
        base
        | name: "Noise_XX_25519_ChaChaPoly_BLAKE3",
          hash: MyApp.Blake3,
          hashlen: MyApp.Blake3.hashlen()
      }

  Keep these invariants, or the peers will derive different keys or the
  handshake will fail:

    * `name` is hashed into the transcript (spec §5.2), so it must be the
      exact spec §8 name of the protocol you run, naming your primitive,
      and both peers must use the same name.
    * `dhlen` must equal `dh.dhlen()` and `hashlen` must equal
      `hash.hashlen()`; they are cached here and used to parse messages.
    * `pattern` must stay consistent with the pattern section of `name`;
      take it from `Noise.Pattern.from_name/1`.

  To swap in a different implementation of an algorithm that already has a
  name (e.g. a hardware-backed X25519), keep `name` unchanged.
  """

  alias Noise.Crypto.Cipher
  alias Noise.Crypto.DH
  alias Noise.Crypto.Hash
  alias Noise.Pattern

  @enforce_keys [:name, :cipher, :dh, :dhlen, :hash, :hashlen, :pattern]
  defstruct [:name, :cipher, :dh, :dhlen, :hash, :hashlen, :pattern]

  @type t() :: %__MODULE__{
          name: String.t(),
          cipher: module(),
          dh: module(),
          dhlen: pos_integer(),
          hash: module(),
          hashlen: 32 | 64,
          pattern: Pattern.t()
        }

  @doc """
  Parses a protocol name such as `"Noise_XX_25519_ChaChaPoly_BLAKE2s"`.

  Raises `ArgumentError` for names that are malformed, longer than 255 bytes
  (spec §8), or that reference an unsupported pattern, modifier or primitive.
  """
  @spec from_name(String.t()) :: t()
  def from_name(name) when is_binary(name) and byte_size(name) <= 255 do
    case String.split(name, "_") do
      ["Noise", pattern, dh, cipher, hash] ->
        dh_mod = parse_dh(dh)
        hash_mod = parse_hash(hash)

        %__MODULE__{
          name: name,
          cipher: parse_cipher(cipher),
          dh: dh_mod,
          dhlen: dh_mod.dhlen(),
          hash: hash_mod,
          hashlen: hash_mod.hashlen(),
          pattern: Pattern.from_name(pattern)
        }

      _ ->
        raise ArgumentError, "Invalid protocol name: #{inspect(name)}"
    end
  end

  def from_name(name) do
    raise ArgumentError,
          "Protocol name must be a string of at most 255 bytes, got: #{inspect(name)}"
  end

  # DH
  @spec generate_keypair(t()) :: DH.keypair()
  def generate_keypair(%__MODULE__{dh: dh}), do: dh.generate_keypair()

  @spec dh(t(), DH.keypair(), DH.pubkey()) :: {:ok, binary()} | {:error, :invalid_public_key}
  def dh(%__MODULE__{dh: dh}, keypair, pubkey), do: dh.dh(keypair, pubkey)

  # Cipher
  @spec encrypt(t(), Cipher.key(), Cipher.nonce(), binary(), binary()) :: binary()
  def encrypt(%__MODULE__{cipher: cipher}, k, n, ad, plain_text),
    do: cipher.encrypt(k, n, ad, plain_text)

  @spec decrypt(t(), Cipher.key(), Cipher.nonce(), binary(), binary()) :: binary() | :error
  def decrypt(%__MODULE__{cipher: cipher}, k, n, ad, cipher_text),
    do: cipher.decrypt(k, n, ad, cipher_text)

  @spec rekey(t(), Cipher.key()) :: Cipher.key()
  def rekey(%__MODULE__{cipher: cipher}, key), do: cipher.rekey(key)

  # Hash
  @spec hash(t(), iodata()) :: Hash.hash()
  def hash(%__MODULE__{hash: hash}, data), do: hash.hash(data)

  @spec hkdf(t(), Hash.hash(), binary(), 2 | 3) ::
          {Hash.hash(), Hash.hash()} | {Hash.hash(), Hash.hash(), Hash.hash()}
  def hkdf(%__MODULE__{hash: hash}, ck, ikm, n), do: hash.hkdf(ck, ikm, n)

  defp parse_dh("25519"), do: Noise.Crypto.DH.X25519
  defp parse_dh("448"), do: Noise.Crypto.DH.X448

  # Decided at compile time, like `Noise.Crypto.DH.Secp256k1` itself, so builds
  # without the optional dependency never reference the missing module.
  if Code.ensure_loaded?(Secp256k1) do
    defp parse_dh("secp256k1"), do: Noise.Crypto.DH.Secp256k1
  else
    defp parse_dh("secp256k1") do
      raise ArgumentError,
            "DH function secp256k1 requires the optional dependency {:lib_secp256k1, \"~> 0.8\"}"
    end
  end

  defp parse_dh(dh), do: raise(ArgumentError, "Unsupported DH function: #{dh}")

  defp parse_cipher("AESGCM"), do: Noise.Crypto.Cipher.AESGCM
  defp parse_cipher("ChaChaPoly"), do: Noise.Crypto.Cipher.ChaChaPoly
  defp parse_cipher(cipher), do: raise(ArgumentError, "Unsupported cipher function: #{cipher}")

  defp parse_hash("SHA256"), do: Noise.Crypto.Hash.Sha256
  defp parse_hash("SHA512"), do: Noise.Crypto.Hash.Sha512
  defp parse_hash("BLAKE2s"), do: Noise.Crypto.Hash.Blake2s
  defp parse_hash("BLAKE2b"), do: Noise.Crypto.Hash.Blake2b
  defp parse_hash(hash), do: raise(ArgumentError, "Unsupported hash function: #{hash}")
end

defimpl Inspect, for: Noise.Protocol do
  def inspect(%Noise.Protocol{name: name}, _opts), do: "#Noise.Protocol<" <> name <> ">"
end
