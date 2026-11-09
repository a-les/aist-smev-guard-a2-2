# nixos/vms/vm-223-garak-pyrit-redteam.nix
# VM 223: Изолированный узел Red-Teaming и нагрузочного тестирования (Панфилов А. В.)
{ config, pkgs, lib, ... }:
{
  system.stateVersion = "25.11";
  networking.hostName = "vm-223-garak-pyrit-redteam";
  networking.interfaces.eth0.ipv4.addresses = [{
    address = "10.221.0.23";
    prefixLength = 24;
  }];
  networking.defaultGateway = "10.221.0.1";
  networking.nameservers = [ "1.1.1.1" ];

  environment.systemPackages = with pkgs; [
    python312
    uv
    k6
    git
    curl
    jq
  ];

  systemd.timers.nightly-gov-redteam-audit = {
    description = "Ежедневный автоматический Red-Team прогон Garak + PyRIT против шлюза VM 221";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "*-*-* 02:30:00";
      Persistent = true;
    };
  };

  systemd.services.nightly-gov-redteam-audit = {
    description = "Запуск оркестратора gov_garak_pyrit_orchestrator.py";
    serviceConfig = {
      Type = "oneshot";
      WorkingDirectory = "/var/lib/aist-smev-guard";
      ExecStart = "${pkgs.uv}/bin/uv run python -m src.redteam.gov_garak_pyrit_orchestrator --target http://10.221.0.21:8080";
    };
  };

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 ];
  };

  services.openssh.enable = true;
}
