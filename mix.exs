defmodule SrpcPlug.Mixfile do
  use Mix.Project

  def project do
    [
      app: :srpc_plug,
      version: "0.1.0",
      description: "Secure Remote Password Cryptor Plug",
      elixir: "~> 1.5",
      deps: deps()
    ] ++ project(Mix.env())
  end

  defp project(:dev) do
    [erlc_options: []]
  end

  # CxTBD The erlc_options don't seem to "take". Pass --no-debug-info to mix compile for now.
  defp project(:prod) do
    [erlc_options: [:no_debug_info, :warnings_as_errors]]
  end

  def application, do: []

  defp deps do
    [
      {:plug, "~> 1.4"},
      {:srpc_srv, path: "local/srpc_srv", compile: false},
      {:srpc_lib, path: "local/srpc_lib", compile: false},
      {:poison, "~> 3.1"}
    ]
  end
end
