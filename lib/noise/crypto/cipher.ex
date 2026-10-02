defmodule Noise.Crypto.Cipher do
  @moduledoc """
  Behaviour for AEAD cipher functions (spec §4.2).

  `decrypt/4` returns `:error` on authentication failure or when the
  ciphertext is shorter than the 16-byte tag. A default `rekey/1`
  (spec §4.2: `ENCRYPT(k, 2^64-1, zerolen, zeros[32])`) is provided by
  `use Noise.Crypto.Cipher`.
  """
  alias Noise.Crypto.Cipher

  @type key() :: <<_::256>>
  @type nonce() :: 0..18_446_744_073_709_551_615

  @callback encrypt(k :: key(), n :: nonce(), ad :: binary(), plain_text :: binary()) ::
              cipher_text :: binary()
  @callback decrypt(k :: key(), n :: nonce(), ad :: binary(), cipher_text :: binary()) ::
              (plain_text :: binary()) | :error
  @callback rekey(key :: key()) :: key()

  @doc "Largest nonce value; reserved for `rekey/1` (spec §5.1)."
  @spec max_nonce() :: nonce()
  def max_nonce, do: 0xFFFF_FFFF_FFFF_FFFF

  defmacro __using__(_opts) do
    quote do
      @behaviour Cipher

      @impl Cipher
      def rekey(k) do
        <<new_key::binary-size(32), _tag::binary>> =
          encrypt(k, Cipher.max_nonce(), <<>>, <<0::256>>)

        new_key
      end

      defoverridable rekey: 1
    end
  end
end
