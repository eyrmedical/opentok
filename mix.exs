defmodule OpenTok.Mixfile do
  use Mix.Project

  def project do
    [
      app: :opentok,
      version: "0.1.4",
      elixir: ">= 1.5.4",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [
      applications: [
        :logger,
        :jose,
        :httpoison,
        :httpotion
      ]
    ]
  end

  # Dependencies can be Hex packages:
  #
  #     {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #     {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:jose, "~> 1.8"},
      {:poison, "~> 3.0"},
      {:hackney, ">= 1.10.1"},
      {:httpoison, "~> 1.4"},
      {:httpotion, ">= 3.0.2"}
    ]
  end
end
