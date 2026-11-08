# nixos/vms/vm-224-pii-vault-postgres.nix
# VM 224: Защищённая СУБД PostgreSQL 16 (Reversible PII Vault + ГОСТ Р 59548-2022 Audit Log)
{ config, pkgs, lib, ... }:
{
  system.stateVersion = "25.11";
  networking.hostName = "vm-224-pii-vault-postgres";
  networking.interfaces.eth0.ipv4.addresses = [{
    address = "10.221.0.24";
    prefixLength = 24;
  }];
  networking.defaultGateway = "10.221.0.1";

  services.postgresql = {
    enable = true;
    package = pkgs.postgresql_16;
    enableTCPIP = true;
    settings = {
      listen_addresses = "10.221.0.24,127.0.0.1";
      max_connections = 120;
      shared_buffers = "1024MB";
      work_mem = "16MB";
      wal_level = "replica";
      fsync = "on";
      synchronous_commit = "on";
      log_connections = "on";
      log_disconnections = "on";
      row_security = "on";
    };
    authentication = pkgs.lib.mkOverride 10 ''
      local all all trust
      host aist_smev_vault aist_guard_app 10.221.0.21/32 scram-sha-256
      host aist_smev_vault aist_guard_app 127.0.0.1/32 scram-sha-256
    '';
    initialScript = pkgs.writeText "init-aist-vault.sql" ''
      CREATE ROLE aist_guard_app WITH LOGIN PASSWORD 'AistGuard2026_Secret!';
      CREATE DATABASE aist_smev_vault OWNER aist_guard_app;
    '';
  };

  services.prometheus.exporters.postgres = {
    enable = true;
    port = 9187;
    runAsLocalSuperUser = true;
  };

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 5432 9187 ];
  };

  services.openssh.enable = true;
}
