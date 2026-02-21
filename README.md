# PortForward

`pfwd` is a single-server port forwarding manager using `iptables`.

## Features
- Run on one server only (no GRE dependency).
- Forward TCP/UDP ports to destination IP:port (per rule).
- Manage rules with one command: add, list, show, update, remove, enable/disable.
- Persistent state in `/etc/pfwd/rules.tsv`.
- Automatic restore at boot with `systemd` service `pfwd-restore.service`.
- Idempotent firewall apply with dedicated chains:
  - `PFWD_PREROUTING`
  - `PFWD_POSTROUTING`
  - `PFWD_FORWARD`

## Install
```bash
sudo ./install.sh
```

This installs:
- `/usr/local/bin/pfwd`
- `/etc/systemd/system/pfwd-restore.service`
- `/etc/pfwd/`

## Quick Start
```bash
sudo pfwd init
sudo pfwd add --proto tcp --listen 0.0.0.0:8080 --to 10.10.10.20:80 --name web
sudo pfwd list
sudo pfwd status
```

Interactive mode (easy menu):
```bash
sudo pfwd
```

## Interactive Workflow
1. Run `sudo pfwd`
2. Choose `1) Quick Add Forward`
3. Enter:
   - protocol (`tcp` or `udp`)
   - listen endpoint (`IP:PORT`, for example `0.0.0.0:443`)
   - destination endpoint (`IP:PORT`, for example `10.0.0.5:8443`)
4. Use:
   - `2) List Forwards` to see all rules
   - `3) Show Forward Details` for exact firewall mapping
   - `6/7` to enable/disable a rule
   - `5` to remove a rule

## Command Reference
```bash
pfwd [--dry-run] [--json] <command> [args]
pfwd   # opens interactive menu (TTY)
```

Commands:
- `init`
- `add --proto tcp|udp --listen IP:PORT --to IP:PORT [--name NAME] [--enable|--disable]`
- `list`
- `show <id>`
- `update <id> [--proto tcp|udp] [--listen IP:PORT] [--to IP:PORT] [--name NAME] [--enable|--disable]`
- `remove <id>`
- `enable <id>`
- `disable <id>`
- `apply`
- `status`
- `flush --managed-only [--purge-state]`
- `export [file]`
- `import <file>`

## Examples
Add UDP forward:
```bash
sudo pfwd add --proto udp --listen 0.0.0.0:5353 --to 10.10.10.30:5353 --name dns
```

Update destination:
```bash
sudo pfwd update 1 --to 10.10.10.99:80
```

Disable then re-enable:
```bash
sudo pfwd disable 1
sudo pfwd enable 1
```

Export/import:
```bash
sudo pfwd export /root/pfwd-backup.tsv
sudo pfwd import /root/pfwd-backup.tsv
```

Dry-run:
```bash
sudo pfwd --dry-run apply
```
