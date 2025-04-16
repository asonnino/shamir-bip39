{
  description = "shamir-bip39 - Shamir's Secret Sharing for BIP-39 mnemonics";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nixos-generators = {
      url = "github:nix-community/nixos-generators";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      nixos-generators,
      ...
    }:
    let
      systemOptions =
        {
          lib,
          pkgs,
          system,
          modulesPath,
          ...
        }:
        {
          imports = [
            (modulesPath + "/profiles/minimal.nix")
            (modulesPath + "/profiles/hardened.nix")
          ];
          # Disable networking
          networking.dhcpcd.enable = false;
          networking.useDHCP = false;
          networking.useNetworkd = false;
          networking.wireless.enable = false;
          networking.networkmanager.enable = false;

          # Disable all storage-related services
          boot.supportedFilesystems = lib.mkForce [ ];
          boot.initrd.supportedFilesystems = lib.mkForce [ ];
          services.udisks2.enable = false;
          security.lockKernelModules = true;

          # Disable all unnecessary services
          services.xserver.enable = false;
          services.printing.enable = false;
          services.openssh.enable = false;

          security.protectKernelImage = true;
          security.forcePageTableIsolation = true;
          boot.kernelParams = [
            # "quiet"
            "loglevel=4"
            "rd.systemd.show_status=false"
            "rd.udev.log_level=2"
            "copytoram"
            "video=vesabf"
            "fbcon=scrollback:128"
          ];

          boot.kernelPatches = [
            {
              name = "minimize";
              patch = null;
              extraConfig = ''
                NET N
              '';
            }
          ];

          # boot.kernelPackages = pkgs.linuxPackagesFor (
          #   pkgs.linuxPackages_latest.kernel.override {
          #     ignoreConfigErrors = true;
          #   }
          # );
          boot.kernelPackages = pkgs.linuxPackages_custom {
            version = pkgs.linuxPackages_latest.kernel.version;
            src = pkgs.linuxPackages_latest.kernel.src;
            configfile = ./nix/minimal-kernel.config;
          };
          environment.sessionVariables = {
            MALLOC_PERTURB_ = ''42'';
          };

          services.nscd.enableNsncd = false;
          services.nscd.enable = false;
          system.nssModules = lib.mkForce [ ];

          # Include only our package
          environment.systemPackages = [
            self.packages.${system}.shamir-bip39
            pkgs.thc-secure-delete
          ];

          systemd.services.secure-memory-wipe = {
            description = "Securely wipe memory on shutdown";
            wantedBy = [ "shutdown.target" ];
            before = [ "shutdown.target" ];
            serviceConfig = {
              Type = "oneshot";
              RemainAfterExit = true;
              StandardOutput = "tty";
              TTYPath = "/dev/console";
              #ExecStart = "${pkgs.coreutils}/bin/true"; # No-op for start
              ExecStart = "${pkgs.thc-secure-delete}/bin/sdmem -v";
            };
            unitConfig = {
              DefaultDependencies = false;
            };
          };

          # Auto-login to console
          services.getty.autologinUser = lib.mkForce "root";

          # Use bash as the shell but add our welcome message
          users.users.root.shell = pkgs.bashInteractive;

          # Add a welcome message via profile
          users.motd = ''
            Welcome to shamir-bip39 secure environment
            This system has no network or persistent storage for security.

            Split a secret:    shamir-bip39 split -t 2 -n 3 --secret "your mnemonic here\"
            Reconstruct:       shamir-bip39 reconstruct --shares "1 word1 word2..." "2 word1 word2..."
            Safe reboot:       reboot
          '';

          # Minimal system
          documentation.enable = false;
          documentation.man.enable = true;
          documentation.info.enable = false;
          documentation.doc.enable = false;

          system.stateVersion = "23.11";
        };
    in
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = rec {
          shamir-bip39 = pkgs.rustPlatform.buildRustPackage {
            pname = "shamir-bip39";
            version = "0.1.0";

            src = nixpkgs.lib.fileset.toSource {
              root = ./.;
              fileset = (
                nixpkgs.lib.fileset.unions [
                  ./Cargo.toml
                  ./Cargo.lock
                  ./assets
                  ./src
                ]
              );
            };

            useFetchCargoVendor = true;
            cargoHash = "sha256-IFFreP1bmw3cZCMrEkYcb5eSL56YcB6Cd5YRzTm4jr0=";

            buildInputs = with pkgs; [
              openssl
            ];

            nativeBuildInputs = with pkgs; [
              pkg-config
              rustc
              cargo
            ];

            # Enable the double-check feature
            buildFeatures = [ "double-check" ];
          };

          default = shamir-bip39;

          # Create a minimal ISO image with just our tool
          iso = nixos-generators.nixosGenerate {
            inherit system;
            modules = [
              (args@{ pkgs, lib, ... }: (systemOptions (args // { inherit system; })))
              {
                isoImage.appendToMenuLabel = " - sahmir-bip39 generator";

                boot.initrd.kernelModules = [
                  "virtio_pci"
                  "virtio_console"
                ];
              }
            ];
            format = "iso";
          };

          # Create a VM image for testing
          vm = nixos-generators.nixosGenerate {
            inherit system;
            modules = [
              (
                args@{ lib, pkgs, ... }:
                (systemOptions (args // { inherit system; }))
                // {
                  boot.initrd.kernelModules = [
                    "virtio_pci"
                    "virtio_console"
                  ];
                }
              )
            ];
            format = "vm";
          };

          # Create a raw disk image
          raw = nixos-generators.nixosGenerate {
            inherit system;
            modules = [
              (
                args@{ pkgs, lib, ... }:
                (systemOptions (args // { inherit system; }))
                // {

                }
              )
            ];
            format = "raw";
          };
        };
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            rustc
            cargo
            cargo-deny
            nixfmt-rfc-style
            rustfmt
            pre-commit
            typos
          ];
        };
      }
    )
    // flake-utils.lib.eachDefaultSystemPassThrough (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        nixosConfigurations = {
          shamir-bip39 = nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              (args@{ ... }: (systemOptions (args // { inherit system pkgs; })))
              (
                { pkgs, lib, ... }:
                {
                  # Basic system configuration
                  boot.loader.systemd-boot.enable = true;
                  boot.loader.efi.canTouchEfiVariables = true;

                  # Set hostname
                  networking.hostName = "shamir-bip39";

                  # Additional security hardening

                  # Disable console messages from displaying on tty

                  # Disable core dumps
                  security.pam.loginLimits = [
                    {
                      domain = "*";
                      item = "core";
                      type = "hard";
                      value = "0";
                    }
                  ];

                  # Disable hibernation (which could leave traces in swap)
                  powerManagement.enable = true;
                  powerManagement.cpuFreqGovernor = "performance";
                  services.logind.lidSwitch = "poweroff";
                  services.logind.extraConfig = ''
                    HandleHibernateKey=poweroff
                    HandleSuspendKey=poweroff
                    HandleLidSwitch=poweroff
                  '';
                }
              )
            ];
          };
        };
      }
    );
}
