defmodule Noise.Vectors.SnowTest do
  use ExUnit.Case, async: true
  alias Noise.VectorRunner

  @moduletag :vectors
  @moduletag :snow

  @vectors_file "test/vectors/snow.json"
  @external_resource @vectors_file

  for vector <- VectorRunner.load_vectors_from_file(@vectors_file) do
    name = vector["name"] || vector["protocol_name"] || "unknown"

    test "snow: #{name}" do
      VectorRunner.run_vector(unquote(Macro.escape(vector)))
    end
  end
end
