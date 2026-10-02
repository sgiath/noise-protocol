defmodule Noise.PatternTest do
  use ExUnit.Case, async: true

  alias Noise.Pattern

  describe "from_name/1" do
    test "parses simple one-way pattern" do
      pattern = Pattern.from_name("N")
      assert pattern.name == "N"
      assert pattern.pre_message == [[], [:s]]
      assert pattern.tokens == [{:ini, [:e, :es]}]
    end

    test "parses interactive pattern NN" do
      pattern = Pattern.from_name("NN")
      assert pattern.name == "NN"
      assert pattern.pre_message == [[], []]
      assert pattern.tokens == [{:ini, [:e]}, {:resp, [:e, :ee]}]
    end

    test "parses pattern with modifiers (psk0)" do
      pattern = Pattern.from_name("NNpsk0")
      assert pattern.name == "NNpsk0"
      # psk0 adds psk to the first message (index 0)
      assert pattern.tokens == [{:ini, [:psk, :e]}, {:resp, [:e, :ee]}]
    end

    test "parses pattern with modifiers (psk2)" do
      # XX has 3 messages: ini, resp, ini.
      # psk2 means adds psk to the end of 2nd message (index 1)
      pattern = Pattern.from_name("XXpsk2")
      assert pattern.name == "XXpsk2"
      # Original XX:
      # -> e
      # <- e, ee, s, es
      # -> s, se

      # Modified XXpsk2:
      # -> e
      # <- e, ee, s, es, psk
      # -> s, se

      expected_tokens = [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s, :es, :psk]},
        {:ini, [:s, :se]}
      ]

      assert pattern.tokens == expected_tokens
    end

    test "parses multiple modifiers" do
      # "NNpsk0+psk2" -> psk at msg 0 (start) and msg 1 (end)
      # psk0 -> prepend to msg 0
      # psk2 -> append to msg 1 (index 1)

      pattern = Pattern.from_name("NNpsk0+psk2")
      assert pattern.name == "NNpsk0+psk2"
      assert pattern.tokens == [{:ini, [:psk, :e]}, {:resp, [:e, :ee, :psk]}]
    end

    test "raises ArgumentError for unsupported base pattern" do
      assert_raise ArgumentError, "Pattern ZZ is not supported", fn ->
        Pattern.from_name("ZZ")
      end
    end

    test "raises ArgumentError for lowercase input" do
      assert_raise ArgumentError, "Pattern noise is not supported", fn ->
        Pattern.from_name("noise")
      end
    end

    test "rejects pskN outside the pattern's message count (spec §9.4)" do
      assert_raise ArgumentError, ~r/psk3 is out of range/, fn -> Pattern.from_name("NNpsk3") end
      assert_raise ArgumentError, ~r/psk2 is out of range/, fn -> Pattern.from_name("Npsk2") end

      assert_raise ArgumentError, ~r/psk01 is out of range/, fn ->
        Pattern.from_name("NNpsk01")
      end

      assert_raise ArgumentError, ~r/psk is out of range/, fn -> Pattern.from_name("NNpsk") end

      assert_raise ArgumentError, ~r/psk-1 is out of range/, fn ->
        Pattern.from_name("NNpsk-1")
      end

      assert_raise ArgumentError, ~r/psk-3 is out of range/, fn ->
        Pattern.from_name("NNpsk-3")
      end
    end

    test "rejects unknown modifiers" do
      assert_raise ArgumentError, ~r/fallback .* not supported/, fn ->
        Pattern.from_name("XXfallback")
      end

      assert_raise ArgumentError, ~r/hfs .* not supported/, fn ->
        Pattern.from_name("NNpsk0+hfs")
      end
    end
  end

  describe "queries" do
    test "psk?/1 and psk_count/1" do
      refute Pattern.psk?(Pattern.from_name("XX"))
      assert Pattern.psk?(Pattern.from_name("XXpsk1"))
      assert Pattern.psk_count(Pattern.from_name("XX")) == 0
      assert Pattern.psk_count(Pattern.from_name("XXpsk0+psk3")) == 2
    end

    test "transmits?/3 and pre_shares?/3" do
      ik = Pattern.from_name("IK")
      assert Pattern.transmits?(ik, :ini, :s)
      refute Pattern.transmits?(ik, :resp, :s)
      assert Pattern.pre_shares?(ik, :resp, :s)
      refute Pattern.pre_shares?(ik, :ini, :s)

      kk = Pattern.from_name("KK")
      assert Pattern.pre_shares?(kk, :ini, :s)
      assert Pattern.pre_shares?(kk, :resp, :s)
      refute Pattern.transmits?(kk, :ini, :s)
      assert Pattern.transmits?(kk, :ini, :e)
    end
  end
end
