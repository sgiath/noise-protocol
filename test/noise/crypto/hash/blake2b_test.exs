defmodule NoiseTest.Crypto.Hash.Blake2b do
  use ExUnit.Case, async: true

  alias Noise.Crypto.Hash.Blake2b

  defp hex(h), do: Base.decode16!(h, case: :lower)

  test "hashlen is 64" do
    assert Blake2b.hashlen() == 64
  end

  test "hash known answers, BLAKE2b-512 (RFC 7693)" do
    assert Blake2b.hash("") ==
             hex(
               "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
             )

    assert Blake2b.hash("abc") ==
             hex(
               "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
             )
  end

  # computed with Python's hmac + hashlib
  test "hmac_hash known answers" do
    assert Blake2b.hmac_hash("Jefe", "what do ya want for nothing?") ==
             hex(
               "6ff884f8ddc2a6586b3c98a4cd6ebdf14ec10204b6710073eb5865ade37a2643b8807c1335d107ecdb9ffeaeb6828c4625ba172c66379efcd222c2de11727ab4"
             )

    # a key longer than the block size is hashed first
    assert Blake2b.hmac_hash(
             :binary.copy(<<0xAA>>, 131),
             "Test Using Larger Than Block-Size Key - Hash Key First"
           ) ==
             hex(
               "a54b2943b2a20227d41ca46c0945af09bc1faefb2f49894c23aebc557fb79c4889dca74408dc865086667aedee4a3185c53a49c80b814c4c5813ea0c8b38a8f8"
             )
  end

  # HKDF(ck, ikm, n) as defined in spec §4.3, computed independently with
  # Python's hmac + hashlib
  test "hkdf known answers for 2 and 3 outputs (spec §4.3)" do
    ck = for i <- 0..63, into: <<>>, do: <<i>>
    ikm = for i <- 0xA0..0xBF, into: <<>>, do: <<i>>

    output1 =
      hex(
        "2c38848136f3485b8bf27c4c4029b7e6dc3abfdcab7c667dbb7e2a9aa3eedec2cffd257aaefa8704035e74fcaa49ab681fdfc5e2a13630e42a4edb9d5daa6eb5"
      )

    output2 =
      hex(
        "eaf690683939cf7f10f52426419ae729d318c22ed35011984575434ba72ff31933c733389da6a84f4073c8160cfc1a7c1552adde961df6204556dc74939ddc2c"
      )

    output3 =
      hex(
        "c4f396fb7d3fc398bef5514a4dfe461b2ce49cc8576ea6ffb53528c28978609a2d3c32c8f1df2c4879ffbf0a4ee878dfdbf64d5da192a2e94b6d69e82a0b4357"
      )

    assert Blake2b.hkdf(ck, ikm, 2) == {output1, output2}
    assert Blake2b.hkdf(ck, ikm, 3) == {output1, output2, output3}
  end
end
