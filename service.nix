flake: { config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkOption types;

  inherit (flake.packages.${pkgs.stdenv.hostPlatform.system}) camoflage;

  cfg = config.services.camoflage;
in
{
  options = {
    services.camoflage = {
      enable = mkEnableOption ''
        CAMOflage Media Proxy
      '';

      package = mkOption {
        type = types.package;
        default = flake.packages.${pkgs.stdenv.hostPlatform.system}.default;
        description = ''
          CAMOflage Package to use
        '';
      };

      port = mkOption {
        type = types.port;
        default = 8081;
        example = 9090;
        description = ''
          Port that CAMOflage will listen on
        '';
      };

      external-domain = mkOption {
        type = types.str;
        default = "camo.example.com";
        description = ''
          The External Domain to be using to generate images
        '';
      };

      external-insecure = mkOption {
        type = types.bool;
        default = false;
        example = false;
        description = ''
          Enable to make CAMOflage generate HTTP:// links instead of HTTPS://
        '';
      };

      via-header = mkOption {
        type = types.str;
        default = "Camoflage Asset Proxy";
        example = "My own Asset Proxy";
        description = ''
          Set the Via: header value sent by CAMOflage
        '';
      };

      secret-key = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          The keyfile to be used with CAMOflage. Otherwise, you can pass it via the CAMO_SECRET_KEY environment variable
        '';
      };

      length-limit = mkOption {
        type = types.int;
        default = 5242880;
        description = "How large media can get until CAMOflage will refuse handling it";
      };
    };
  };

  config = lib.mkIf cfg.enable {

    services.nginx.virtualHosts.${cfg.external-domain} = {
      serverName = cfg.external-domain;
      locations."/" = {
        proxyPass = "http://127.0.0.1:${toString cfg.port}/";
        proxyWebsockets = true;
        recommendedProxySettings = true;
      };
    };

    systemd.services.camoflage = {
      description = "CAMOflage Media Proxy";

      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Restart = "on-failure";
        ExecStart = ''${lib.getBin cfg.package}/bin/camoflage
          --port ${toString cfg.port}
          --external-domain ${cfg.external-domain}
          --via-header ${cfg.via-header}
          --secret-key file://${toString cfg.secret-key}
          --length-limit ${toString cfg.length-limit}
        '';
        StateDirectory = "camoflage";
        StateDirectoryMode = "0750";

        CapabilityBoundingSet = [ "AF_NETLINK" "AF_INET" "AF_INET6" ];
        LockPersonality = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        PrivateUsers = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        ReadOnlyPaths = [ "/" ];
        RemoveIPC = true;
        RestrictAddressFamilies = [ "AF_NETLINK" "AF_INET" "AF_INET6" ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" "@pkey" ];
        UMask = "0027";
      };
    };
  };
}