# nixos/vms/vm-221-smev-ai-guard-gpu.nix
# VM 221: Главный шлюз безопасности СМЭВ-Guard + GPU RTX 5080 (Селезнева О. С. + Панфилов А. В.)
{ config, pkgs, lib, ... }:
{
  system.stateVersion = "25.11";
  networking.hostName = "vm-221-smev-ai-guard-gpu";
  networking.interfaces.eth0.ipv4.addresses = [{
    address = "10.221.0.21";
    prefixLength = 24;
  }];
  networking.defaultGateway = "10.221.0.1";
  networking.nameservers = [ "1.1.1.1" "8.8.8.8" ];

  # Драйвер NVIDIA Open Kernel Module для архитектуры Blackwell (RTX 5080 sm_120)
  services.xserver.videoDrivers = [ "nvidia" ];
  hardware.graphics.enable = true;
  hardware.nvidia = {
    modesetting.enable = true;
    open = true;
    nvidiaSettings = false;
    package = config.boot.kernelPackages.nvidiaPackages.production;
  };

  environment.systemPackages = with pkgs; [
    python312
    uv
    git
    z3
    open-policy-agent
    postgresql_16
    pciutils
    nvtopPackages.nvidia
    curl
    jq
  ];

  users.users.aistguard = {
    isSystemUser = true;
    group = "aistguard";
    home = "/var/lib/aist-smev-guard";
    createHome = true;
  };
  users.groups.aistguard = {};

  systemd.services.aist-smev-guard-gateway = {
    description = "Щит-АИСТ / СМЭВ-Guard FastAPI Security Gateway (152-FZ PII + 3-Stage Prompt Shield + Z3)";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    wantedBy = [ "multi-user.target" ];
    environment = {
      PYTHONPATH = "/var/lib/aist-smev-guard";
      AIST_GUARD_DB_DSN = "postgresql://aist_guard_app:AistGuard2026_Secret!@10.221.0.24:5432/aist_smev_vault";
      AIST_UPSTREAM_LLM_URL = "http://10.221.0.22:8000/v1";
      AIST_MASTER_KEY_HEX = "8f4a9c2e1b7d6053a9e8f1c4b2d70395e6a1c8f3b4d29071a5c6e8f0d3b2a194";
      AIST_CANARY_TOKEN = "[CANARY-GOV-AIST-9F8A-2026]";
      OMP_NUM_THREADS = "4";
    };
    serviceConfig = {
      User = "aistguard";
      Group = "aistguard";
      WorkingDirectory = "/var/lib/aist-smev-guard";
      ExecStart = "${pkgs.uv}/bin/uv run uvicorn src.api.main:app --host 0.0.0.0 --port 8080 --workers 2";
      Restart = "always";
      RestartSec = "3s";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/var/lib/aist-smev-guard" ];
    };
  };

  services.prometheus.exporters.node = {
    enable = true;
    port = 9100;
    enabledCollectors = [ "systemd" "cpu" "meminfo" "netdev" ];
  };

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 8080 9100 ];
  };

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "prohibit-password";
    settings.PasswordAuthentication = false;
  };
}
