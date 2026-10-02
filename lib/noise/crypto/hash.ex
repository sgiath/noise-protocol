defmodule Noise.Crypto.Hash do
  @moduledoc """
  Behaviour for hash functions (spec §4.3).

  Implementations provide `hashlen/0`, `hash/1` and `hmac_hash/2`;
  `hkdf/3` (spec §4.3) is derived from `hmac_hash/2` by `use Noise.Crypto.Hash`.
  """
  @type hash() :: <<_::256>> | <<_::512>>

  @callback hashlen() :: 32 | 64
  @callback hash(data :: iodata()) :: hash()
  @callback hmac_hash(key :: binary(), data :: iodata()) :: hash()
  @callback hkdf(
              chaining_key :: hash(),
              input_key_material :: binary(),
              num_outputs :: 2 | 3
            ) ::
              {output1 :: hash(), output2 :: hash()}
              | {output1 :: hash(), output2 :: hash(), output3 :: hash()}

  defmacro __using__(_opts) do
    quote do
      @behaviour Noise.Crypto.Hash

      @impl Noise.Crypto.Hash
      def hkdf(chaining_key, input_key_material, 2) do
        temp_key = hmac_hash(chaining_key, input_key_material)
        output1 = hmac_hash(temp_key, <<0x01>>)
        output2 = hmac_hash(temp_key, <<output1::binary, 0x02>>)
        {output1, output2}
      end

      def hkdf(chaining_key, input_key_material, 3) do
        temp_key = hmac_hash(chaining_key, input_key_material)
        output1 = hmac_hash(temp_key, <<0x01>>)
        output2 = hmac_hash(temp_key, <<output1::binary, 0x02>>)
        output3 = hmac_hash(temp_key, <<output2::binary, 0x03>>)
        {output1, output2, output3}
      end
    end
  end
end
