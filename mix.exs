defmodule Noise.MixProject do
  use Mix.Project

  @version "0.3.0"

  def project do
    [
      # Library
      app: :noise_protocol,
      version: @version,
      elixir: "~> 1.18",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      consolidate_protocols: Mix.env() != :test,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),

      # Docs
      name: "Noise Protocol",
      source_url: "https://github.com/sgiath/noise-protocol",
      homepage_url: "https://sgiath.dev/libraries#noise-protocol",
      description: """
      Library implementing Noise protocol
      """,
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Optional: only needed for the `secp256k1` DH function
      {:lib_secp256k1, "~> 0.8", optional: true},

      # Development
      {:ex_check, "~> 0.16", only: [:dev], runtime: false},
      {:credo, "~> 1.7", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.40", only: [:dev], runtime: false},
      {:mix_audit, "~> 2.1", only: [:dev], runtime: false},
      {:mix_test_watch, "~> 1.4", only: [:dev], runtime: false}
    ]
  end

  defp package do
    [
      name: "noise_protocol",
      maintainers: ["sgiath <noise@sgiath.dev>"],
      files: ~w(lib LICENSE mix.exs README* CHANGELOG*),
      licenses: ["WTFPL"],
      links: %{
        "Noise Homepage" => "https://noiseprotocol.org/",
        "GitHub" => "https://github.com/sgiath/noise-protocol"
      }
    ]
  end

  defp docs do
    [
      authors: ["sgiath <noise@sgiath.dev>"],
      main: "Noise",
      extras: [
        "CHANGELOG.md": [filename: "changelog", title: "Changelog"],
        "README.md": [filename: "readme", title: "Readme"],
        specification: [url: "https://noiseprotocol.org/noise.html", title: "Specification"]
      ],
      formatters: ["html"],
      source_ref: "v#{@version}",
      source_url: "https://github.com/sgiath/noise-protocol",
      groups_for_modules: groups_for_modules()
    ]
  end

  defp groups_for_modules do
    [
      Handshake: [
        Noise.Protocol,
        Noise.Pattern,
        Noise.HandshakeState,
        Noise.SymmetricState,
        Noise.CipherState
      ],
      Ciphers: [Noise.Crypto.Cipher, Noise.Crypto.Cipher.AESGCM, Noise.Crypto.Cipher.ChaChaPoly],
      "Diffie-Hellman": [
        Noise.Crypto.DH,
        Noise.Crypto.DH.X25519,
        Noise.Crypto.DH.X448,
        Noise.Crypto.DH.Secp256k1
      ],
      Hashes: [
        Noise.Crypto.Hash,
        Noise.Crypto.Hash.Sha256,
        Noise.Crypto.Hash.Sha512,
        Noise.Crypto.Hash.Blake2b,
        Noise.Crypto.Hash.Blake2s
      ]
    ]
  end
end
