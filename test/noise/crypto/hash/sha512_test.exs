defmodule NoiseTest.Crypto.Hash.Sha512 do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Sha512

  defp hex(h), do: Base.decode16!(h, case: :lower)

  test "hashlen is 64" do
    assert Sha512.hashlen() == 64
  end

  test "hash known answers, SHA-512 (FIPS 180-4)" do
    assert Sha512.hash("") ==
             hex(
               "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
             )

    assert Sha512.hash("abc") ==
             hex(
               "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
             )
  end

  # RFC 4231 test cases 2 and 6
  test "hmac_hash known answers" do
    assert Sha512.hmac_hash("Jefe", "what do ya want for nothing?") ==
             hex(
               "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
             )

    # a key longer than the block size is hashed first
    assert Sha512.hmac_hash(
             :binary.copy(<<0xAA>>, 131),
             "Test Using Larger Than Block-Size Key - Hash Key First"
           ) ==
             hex(
               "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
             )
  end

  # HKDF(ck, ikm, n) as defined in spec §4.3, computed independently with
  # Python's hmac + hashlib
  test "hkdf known answers for 2 and 3 outputs (spec §4.3)" do
    ck = for i <- 0..63, into: <<>>, do: <<i>>
    ikm = for i <- 0xA0..0xBF, into: <<>>, do: <<i>>

    output1 =
      hex(
        "67ccb1f28f2fbe60b123cb992cdeec29ea4b96d88bea12441f863e3ffc29235235b16e6bc575beb637382a7fefa63b25b7e4a1b85626fa61912a4a529e1db025"
      )

    output2 =
      hex(
        "85f7c3484c50b14386f103ffbcc661e769655be1859e26b1b8837e5cbf6b82f634e885b882ff1d69f09cc603eddcd787284c3bae73259e0ea126853b7c6c9f75"
      )

    output3 =
      hex(
        "ff682c9ae5ed1ce60ab7fa0bae6b0465fd8afbd65bbb0e48ed2dab436330cc01fd1e048b355556e45ae7722375d8c65626982737ecd507c089a9f38e84342c1d"
      )

    assert Sha512.hkdf(ck, ikm, 2) == {output1, output2}
    assert Sha512.hkdf(ck, ikm, 3) == {output1, output2, output3}
  end
end
