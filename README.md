# tsblock

[![Licensed under GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![CI](https://github.com/ciffelia/tsblock/actions/workflows/ci.yaml/badge.svg)](https://github.com/ciffelia/tsblock/actions/workflows/ci.yaml)

tsblock prevents Tailscale from using specific network interfaces.

tsblock is developed to work around [tailscale/tailscale#7594](https://github.com/tailscale/tailscale/issues/7594). Currently, interfaces whose name matches `^cilium_|^lxc` are blocked. The pattern is hard-coded in [main.go](main.go).

## Requirements

- Tailscale must be running as a systemd service.
- tsblock must run as root. It is recommended to run tsblock as a systemd service.

## How it works

tsblock utilizes eBPF to drop packets sent from `tailscaled.service` systemd unit.

## Install

```
go build
sudo ./systemd/install.sh
sudo systemctl daemon-reload
sudo systemctl enable --now tsblock.service
```

## Uninstall

```
sudo systemctl disable --now tsblock.service
sudo ./systemd/uninstall.sh
```
