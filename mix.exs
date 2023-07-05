defmodule OpenTok.Mixfile do
  use Mix.Project

  def project do
    [
      app: :opentok,
      version: "0.2.0",
      elixir: "~> 1.14",
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
      extra_applications: [:crypto, :logger]
    ]
  end

  defp deps do
    [
      {:jose, "~> 1.9"},
      {:poison, "~> 5.0"},
      {:hackney, "~> 1.18"},
      {:httpoison, "~> 1.4"}
    ]
  end
end
