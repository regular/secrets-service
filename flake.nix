{
  description = "Secure secrets service with memory protection";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, crane}:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ 
          rust-overlay.overlays.default
          self.overlays.default
        ];
      };
    in
    {
      overlays.default = final: prev: {
        crane = crane.mkLib final;
      };
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.secrets;
        in
        {
          options.services.secrets = with lib; {
            enable = mkEnableOption "secrets service";

            store = mkOption {
              type = types.path;
              default = "/var/lib/secrets";
              description = "Path where encrypted secrets are stored";
            };

            timeout = mkOption {
              type = types.int;
              default = 900; # 15 minutes
              description = "Key cache timeout in seconds";
            };

            socketPath = mkOption {
              type = types.path;
              default = "/run/secrets-service.sock";
              description = "Unix domain socket path";
            };

            user = mkOption {
              type = types.str;
              default = "root";
              description = "User to run the service as";
            };

            group = mkOption {
              type = types.str;
              default = "root";
              description = "Group to run the service as";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.secrets = {
              description = "Secrets encryption service";
              documentation = [ "https://github.com/regular/secrets-service" ];
              
              serviceConfig = {
                Type = "simple";
                ExecStart = "${self.packages.${pkgs.system}.default}/bin/secrets-service";
                User = cfg.user;
                Group = cfg.group;
                
                # Security hardening
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [ "AF_UNIX" ];
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                MemoryDenyWriteExecute = true;
                LockPersonality = true;
                NoNewPrivileges = true;
                
                # Resource limits
                LimitNOFILE = 1024;
                LimitNPROC = 64;
                
                # Runtime directory
                RuntimeDirectory = "secrets-service";
                StateDirectory = "secrets";
                RuntimeDirectoryMode = "0700";
                
                # Environment
                Environment = [
                  "SECRETS_STORE=${cfg.store}"
                  "SECRETS_TIMEOUT=${toString cfg.timeout}"
                  "SECRETS_SOCKET=${cfg.socketPath}"
                ];
                
                # Startup
                Restart = "on-failure";
                RestartSec = "5s";
              };

              wantedBy = [ "multi-user.target" ];
              
              #preStart = ''
              #  mkdir -p ${cfg.store}
              #  chmod 700 ${cfg.store}
              #'';
            };

            # Ensure the store directory exists and has correct permissions
            system.activationScripts.secrets-store = ''
              mkdir -p ${cfg.store}
              chmod 700 ${cfg.store}
            '';

            environment.systemPackages = [
              (pkgs.writeScriptBin "secretsctl" ''
                #!${pkgs.bash}/bin/bash
                SECRETS_SOCKET="${cfg.socketPath}"
                ${builtins.readFile ./secretsctl.sh}
              '')
            ];
          };
        };

        devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              # Rust toolchain
              rust-overlay.packages.${system}.rust-nightly
              rust-analyzer

              # Dependencies
              pkg-config
              libsodium

              # Development tools
              cargo-watch
              cargo-edit
            ];

            # Set environment variables
            RUST_SRC_PATH = pkgs.rust.packages.stable.rustPlatform.rustLibSrc;
          };
        });

      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          craneLib = pkgs.crane;
          
          commonArgs = {
            src = ./.;
            buildInputs = with pkgs; [
              libsodium
            ];
            
            nativeBuildInputs = with pkgs; [
              pkg-config
              rust-overlay.packages.${system}.rust-nightly
            ];
          };
          
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          
          secrets-service = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
        in
        {
          default = secrets-service;
        });
    };
}
