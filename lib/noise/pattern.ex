defmodule Noise.Pattern do
  @moduledoc """
  A handshake pattern (spec §7): pre-messages and message token sequences.

  `from_name/1` resolves a pattern name such as `"IK"`, `"XXpsk2"` or
  `"NNpsk0+psk2"` — every one-way, fundamental and deferred pattern from
  spec §7.4-§7.6 plus the `pskN` modifiers of §9.4. Unknown patterns and
  invalid modifiers (`psk9` on a two-message pattern, `fallback`, …) raise
  `ArgumentError`.
  """

  @enforce_keys [:name]
  defstruct name: nil, pre_message: [[], []], tokens: []

  @type token() :: :e | :s | :ee | :se | :es | :ss | :psk
  @type role() :: :ini | :resp
  @typedoc "Pre-message tokens of one party: `[]`, `[:e]`, `[:s]` or `[:e, :s]` (spec §7.1)."
  @type pre_message() :: [:e | :s]
  @type t() :: %__MODULE__{
          name: String.t(),
          pre_message: [pre_message()],
          tokens: [{role(), [token()]}]
        }

  @spec from_name(String.t()) :: t()
  def from_name(name) do
    case Regex.run(~r/^([A-Z0-9]+)(.*)$/, name) do
      [_, base_name, modifiers_str] ->
        base_name
        |> get_base_pattern()
        |> apply_modifiers(name, modifiers_str)

      _ ->
        raise ArgumentError, "Pattern #{name} is not supported"
    end
  end

  @doc "Whether any message carries a `psk` token (spec §9.2 changes `e` handling)."
  @spec psk?(t()) :: boolean()
  def psk?(%__MODULE__{tokens: tokens}), do: Enum.any?(tokens, fn {_role, t} -> :psk in t end)

  @doc "Number of `psk` tokens, i.e. the number of pre-shared keys each party needs."
  @spec psk_count(t()) :: non_neg_integer()
  def psk_count(%__MODULE__{tokens: tokens}) do
    tokens |> Enum.flat_map(fn {_role, t} -> t end) |> Enum.count(&(&1 == :psk))
  end

  @doc "Whether `role` sends `token` (`:e` or `:s`) in one of its handshake messages."
  @spec transmits?(t(), role(), :e | :s) :: boolean()
  def transmits?(%__MODULE__{tokens: tokens}, role, token) do
    Enum.any?(tokens, fn {r, t} -> r == role and token in t end)
  end

  @doc "Whether `role`'s `token` (`:e` or `:s`) is a pre-message, known to the peer up front."
  @spec pre_shares?(t(), role(), :e | :s) :: boolean()
  def pre_shares?(%__MODULE__{pre_message: [ini_pre, _]}, :ini, token), do: token in ini_pre
  def pre_shares?(%__MODULE__{pre_message: [_, resp_pre]}, :resp, token), do: token in resp_pre

  @doc "Whether this is a one-way pattern (spec §7.4): a single initiator→responder message."
  @spec one_way?(t()) :: boolean()
  def one_way?(%__MODULE__{tokens: tokens}), do: match?([{:ini, _}], tokens)

  defp apply_modifiers(pattern, full_name, "") do
    %{pattern | name: full_name}
  end

  defp apply_modifiers(pattern, full_name, modifiers_str) do
    tokens =
      modifiers_str
      |> String.split("+")
      |> Enum.reduce(pattern.tokens, &apply_modifier(&1, &2, full_name))

    %{pattern | name: full_name, tokens: tokens}
  end

  # psk0 prepends to the first message; pskN (N >= 1) appends to the Nth message (spec §9.4)
  defp apply_modifier("psk" <> n, tokens, full_name) do
    with {i, ""} <- Integer.parse(n),
         true <- Integer.to_string(i) == n and i >= 0 and i <= length(tokens) do
      insert_psk(tokens, i)
    else
      _ -> raise ArgumentError, "Modifier psk#{n} is out of range for pattern #{full_name}"
    end
  end

  defp apply_modifier(modifier, _tokens, full_name) do
    raise ArgumentError, "Modifier #{modifier} in pattern #{full_name} is not supported"
  end

  defp insert_psk(tokens, 0),
    do: List.update_at(tokens, 0, fn {role, t} -> {role, [:psk | t]} end)

  defp insert_psk(tokens, i),
    do: List.update_at(tokens, i - 1, fn {role, t} -> {role, t ++ [:psk]} end)

  # One way
  defp get_base_pattern("N") do
    %__MODULE__{name: "N", pre_message: [[], [:s]], tokens: [{:ini, [:e, :es]}]}
  end

  defp get_base_pattern("K") do
    %__MODULE__{name: "K", pre_message: [[:s], [:s]], tokens: [{:ini, [:e, :es, :ss]}]}
  end

  defp get_base_pattern("X") do
    %__MODULE__{name: "X", pre_message: [[], [:s]], tokens: [{:ini, [:e, :es, :s, :ss]}]}
  end

  # Interactive
  defp get_base_pattern("NN") do
    %__MODULE__{name: "NN", tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}]}
  end

  defp get_base_pattern("KN") do
    %__MODULE__{
      name: "KN",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :se]}]
    }
  end

  defp get_base_pattern("NK") do
    %__MODULE__{
      name: "NK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es]}, {:resp, [:e, :ee]}]
    }
  end

  defp get_base_pattern("KK") do
    %__MODULE__{
      name: "KK",
      pre_message: [[:s], [:s]],
      tokens: [{:ini, [:e, :es, :ss]}, {:resp, [:e, :ee, :se]}]
    }
  end

  defp get_base_pattern("NX") do
    %__MODULE__{name: "NX", tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s, :es]}]}
  end

  defp get_base_pattern("KX") do
    %__MODULE__{
      name: "KX",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :se, :s, :es]}]
    }
  end

  defp get_base_pattern("XN") do
    %__MODULE__{name: "XN", tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}, {:ini, [:s, :se]}]}
  end

  defp get_base_pattern("IN") do
    %__MODULE__{name: "IN", tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee, :se]}]}
  end

  defp get_base_pattern("XK") do
    %__MODULE__{
      name: "XK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es]}, {:resp, [:e, :ee]}, {:ini, [:s, :se]}]
    }
  end

  defp get_base_pattern("IK") do
    %__MODULE__{
      name: "IK",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e, :es, :s, :ss]}, {:resp, [:e, :ee, :se]}]
    }
  end

  defp get_base_pattern("XX") do
    %__MODULE__{
      name: "XX",
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s, :es]}, {:ini, [:s, :se]}]
    }
  end

  defp get_base_pattern("IX") do
    %__MODULE__{name: "IX", tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee, :se, :s, :es]}]}
  end

  # Deferred patterns

  # One-way deferred
  defp get_base_pattern("X1N") do
    %__MODULE__{
      name: "X1N",
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}, {:ini, [:s]}, {:resp, [:se]}]
    }
  end

  defp get_base_pattern("K1N") do
    %__MODULE__{
      name: "K1N",
      pre_message: [[:s], []],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee]}, {:ini, [:se]}]
    }
  end

  defp get_base_pattern("I1N") do
    %__MODULE__{
      name: "I1N",
      tokens: [{:ini, [:e, :s]}, {:resp, [:e, :ee]}, {:ini, [:se]}]
    }
  end

  # Interactive deferred
  defp get_base_pattern("NK1") do
    %__MODULE__{
      name: "NK1",
      pre_message: [[], [:s]],
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :es]}]
    }
  end

  defp get_base_pattern("NX1") do
    %__MODULE__{
      name: "NX1",
      tokens: [{:ini, [:e]}, {:resp, [:e, :ee, :s]}, {:ini, [:es]}]
    }
  end

  defp get_base_pattern("X1K") do
    %__MODULE__{
      name: "X1K",
      pre_message: [[], [:s]],
      tokens: [
        {:ini, [:e, :es]},
        {:resp, [:e, :ee]},
        {:ini, [:s]},
        {:resp, [:se]}
      ]
    }
  end

  defp get_base_pattern("XK1") do
    %__MODULE__{
      name: "XK1",
      pre_message: [[], [:s]],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :es]},
        {:ini, [:s, :se]}
      ]
    }
  end

  defp get_base_pattern("X1K1") do
    %__MODULE__{
      name: "X1K1",
      pre_message: [[], [:s]],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :es]},
        {:ini, [:s]},
        {:resp, [:se]}
      ]
    }
  end

  defp get_base_pattern("X1X") do
    %__MODULE__{
      name: "X1X",
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s, :es]},
        {:ini, [:s]},
        {:resp, [:se]}
      ]
    }
  end

  defp get_base_pattern("XX1") do
    %__MODULE__{
      name: "XX1",
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s]},
        {:ini, [:es, :s, :se]}
      ]
    }
  end

  defp get_base_pattern("X1X1") do
    %__MODULE__{
      name: "X1X1",
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s]},
        {:ini, [:es, :s]},
        {:resp, [:se]}
      ]
    }
  end

  defp get_base_pattern("K1K") do
    %__MODULE__{
      name: "K1K",
      pre_message: [[:s], [:s]],
      tokens: [
        {:ini, [:e, :es]},
        {:resp, [:e, :ee]},
        {:ini, [:se]}
      ]
    }
  end

  defp get_base_pattern("KK1") do
    %__MODULE__{
      name: "KK1",
      pre_message: [[:s], [:s]],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :se, :es]}
      ]
    }
  end

  defp get_base_pattern("K1K1") do
    %__MODULE__{
      name: "K1K1",
      pre_message: [[:s], [:s]],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :es]},
        {:ini, [:se]}
      ]
    }
  end

  defp get_base_pattern("K1X") do
    %__MODULE__{
      name: "K1X",
      pre_message: [[:s], []],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s, :es]},
        {:ini, [:se]}
      ]
    }
  end

  defp get_base_pattern("KX1") do
    %__MODULE__{
      name: "KX1",
      pre_message: [[:s], []],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :se, :s]},
        {:ini, [:es]}
      ]
    }
  end

  defp get_base_pattern("K1X1") do
    %__MODULE__{
      name: "K1X1",
      pre_message: [[:s], []],
      tokens: [
        {:ini, [:e]},
        {:resp, [:e, :ee, :s]},
        {:ini, [:se, :es]}
      ]
    }
  end

  defp get_base_pattern("I1K") do
    %__MODULE__{
      name: "I1K",
      pre_message: [[], [:s]],
      tokens: [
        {:ini, [:e, :es, :s]},
        {:resp, [:e, :ee]},
        {:ini, [:se]}
      ]
    }
  end

  defp get_base_pattern("IK1") do
    %__MODULE__{
      name: "IK1",
      pre_message: [[], [:s]],
      tokens: [
        {:ini, [:e, :s]},
        {:resp, [:e, :ee, :se, :es]}
      ]
    }
  end

  defp get_base_pattern("I1K1") do
    %__MODULE__{
      name: "I1K1",
      pre_message: [[], [:s]],
      tokens: [
        {:ini, [:e, :s]},
        {:resp, [:e, :ee, :es]},
        {:ini, [:se]}
      ]
    }
  end

  defp get_base_pattern("I1X") do
    %__MODULE__{
      name: "I1X",
      tokens: [
        {:ini, [:e, :s]},
        {:resp, [:e, :ee, :s, :es]},
        {:ini, [:se]}
      ]
    }
  end

  defp get_base_pattern("IX1") do
    %__MODULE__{
      name: "IX1",
      tokens: [
        {:ini, [:e, :s]},
        {:resp, [:e, :ee, :se, :s]},
        {:ini, [:es]}
      ]
    }
  end

  defp get_base_pattern("I1X1") do
    %__MODULE__{
      name: "I1X1",
      tokens: [
        {:ini, [:e, :s]},
        {:resp, [:e, :ee, :s]},
        {:ini, [:se, :es]}
      ]
    }
  end

  defp get_base_pattern(pattern) do
    raise ArgumentError, "Pattern #{pattern} is not supported"
  end
end

defimpl Inspect, for: Noise.Pattern do
  # e.g. #Noise.Pattern<IK: <- s ... -> e, es, s, ss | <- e, ee, se>
  def inspect(%Noise.Pattern{name: name, pre_message: pre, tokens: tokens}, _opts) do
    pre_messages =
      pre
      |> Enum.zip([:ini, :resp])
      |> Enum.reject(fn {t, _} -> t == [] end)
      |> Enum.map_join(" ", fn {t, role} -> message(role, t) end)

    messages = Enum.map_join(tokens, " | ", fn {role, t} -> message(role, t) end)
    prefix = if pre_messages == "", do: "", else: pre_messages <> " ... "

    "#Noise.Pattern<" <> name <> ": " <> prefix <> messages <> ">"
  end

  defp message(:ini, tokens), do: "-> " <> Enum.join(tokens, ", ")
  defp message(:resp, tokens), do: "<- " <> Enum.join(tokens, ", ")
end
