# flake.nix
# Единый декларативный контур Команды А2.2 (Селезнева О. С. + Панфилов А. В.)
{
  description = "Team A2.2 (Selezneva & Panfilov) — GovTech AIST/SMEV-Guard + 152-FZ PII Vault + ViPNet Z3 SMT + FSTEC #117 (NixOS 25.11)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        config = {
          allowUnfree = true;
          cudaSupport = true;
        };
      };
    in
    {
      nixosConfigurations = {
        vm-221-smev-ai-guard-gpu = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [ ./nixos/vms/vm-221-smev-ai-guard-gpu.nix ];
        };
        vm-222-aist-mock-gov-llm = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [ ./nixos/vms/vm-222-aist-mock-gov-llm.nix ];
        };
        vm-223-garak-pyrit-redteam = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [ ./nixos/vms/vm-223-garak-pyrit-redteam.nix ];
        };
        vm-224-pii-vault-postgres = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [ ./nixos/vms/vm-224-pii-vault-postgres.nix ];
        };
        vm-225-prometheus-grafana-soc = nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [ ./nixos/vms/vm-225-prometheus-grafana-soc.nix ];
        };
      };

      devShells.${system}.default = pkgs.mkShell {
        buildInputs = with pkgs; [
          python312
          uv
          git
          jq
          z3
          open-policy-agent
          postgresql_16
          k6
          openssl
          libxml2
          ruff
        ];

        shellHook = ''
          export VIRTUAL_ENV=".venv"
          export AIST_GUARD_DB_DSN="postgresql://aist_guard_app:AistGuard2026_Secret!@10.221.0.24:5432/aist_smev_vault"
          export AIST_UPSTREAM_LLM_URL="http://10.221.0.22:8000/v1"
          export AIST_MASTER_KEY_HEX="8f4a9c2e1b7d6053a9e8f1c4b2d70395e6a1c8f3b4d29071a5c6e8f0d3b2a194"
          export AIST_CANARY_TOKEN="[CANARY-GOV-AIST-9F8A-2026]"
          echo "[Team A2.2 nix-shell] Контур «Щит-АИСТ / СМЭВ-Guard & ViPNet Z3» (Селезнева О. С. & Панфилов А. В.) активирован."
        '';
      };
    };
}
