{
  description = "Noise Protocol Elixir lib";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    expert.url = "github:expert-lsp/expert";
  };

  outputs =
    { nixpkgs, expert, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      beamPackages = pkgs.beamMinimal29Packages.overrideScope (
        _final: prev: {
          elixir = prev.elixir_1_20;
        }
      );
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          beamPackages.elixir
          git
          autoreconfHook
          libsodium

          # tooling
          (expert.packages.${system}.default.override { inherit beamPackages; })
          nixd
          nixfmt
        ];

        env = {
          ERL_AFLAGS = "+pc unicode -kernel shell_history enabled";
          ELIXIR_ERL_OPTIONS = "+sssdio 128";
        };
      };
    };
}
