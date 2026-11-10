# nixos/vms/vm-225-prometheus-grafana-soc.nix
# VM 225: Центр мониторинга ИБ ГИС К1 (Prometheus + Grafana + Alertmanager)
{ config, pkgs, lib, ... }:
let
  alertRulesFile = pkgs.writeText "aist-fstec-alerts.yml" ''
    groups:
      - name: aist_smev_guard_fstec_k1
        rules:
          - alert: FstecUziCriticalDropZero
            expr: aist_guard_fstec_uzi_score < 0.85
            for: 10s
            labels:
              severity: critical
              fstec_measure: "ЗИС.3 / МСЭ.3 / ЗКС.1"
            annotations:
              summary: "Показатель защищённости ГИС Узи упал ниже порога 0.85 (или I_block=0)"
          - alert: GovPromptInjectionSpike
            expr: rate(aist_guard_prompt_injections_blocked_total[5m]) > 0.5
            for: 30s
            labels:
              severity: high
              fstec_measure: "МД ФСТЭК 12.04.2026 ИИ"
            annotations:
              summary: "Зафиксирована серия попыток Prompt Injection / RAG Poisoning на шлюз АИСТ"
          - alert: GostStreebogAuditChainBroken
            expr: aist_guard_streebog_chain_valid == 0
            for: 1s
            labels:
              severity: critical
              fstec_measure: "ГОСТ Р 59548-2022 / РСБ.1"
            annotations:
              summary: "НАРУШЕНА ЦЕЛОСТНОСТЬ ЦЕПОЧКИ ХЕШЕЙ СТРИБОГ-256 В ЖУРНАЛЕ АУДИТА!"
  '';
in
{
  system.stateVersion = "25.11";
  networking.hostName = "vm-225-prometheus-grafana-soc";
  networking.interfaces.eth0.ipv4.addresses = [{
    address = "10.221.0.25";
    prefixLength = 24;
  }];
  networking.defaultGateway = "10.221.0.1";

  services.prometheus = {
    enable = true;
    port = 9090;
    scrapeInterval = "5s";
    ruleFiles = [ alertRulesFile ];
    scrapeConfigs = [
      {
        job_name = "aist-smev-guard-gateway";
        static_configs = [{ targets = [ "10.221.0.21:8080" "10.221.0.21:9100" ]; }];
      }
      {
        job_name = "pii-vault-postgres";
        static_configs = [{ targets = [ "10.221.0.24:9187" ]; }];
      }
    ];
  };

  services.grafana = {
    enable = true;
    settings = {
      server = {
        http_addr = "0.0.0.0";
        http_port = 3000;
      };
      security = {
        admin_user = "soc_admin";
        admin_password = "GuitSoc2026_Password!";
      };
    };
  };

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 3000 9090 ];
  };

  services.openssh.enable = true;
}
