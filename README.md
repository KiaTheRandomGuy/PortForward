# PortForward

`pfwd` is a single-server port forward manager (TCP/UDP) using Linux `iptables`.

## Install (from GitHub)
Run these commands on your server:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/KiaTheRandomGuy/PortForward.git
cd PortForward
sudo ./install.sh
```

One-line install + run (recommended):

```bash
curl -fsSL https://raw.githubusercontent.com/KiaTheRandomGuy/PortForward/main/bootstrap.sh | sudo bash
```

What install does:
- installs `pfwd` to `/usr/local/bin/pfwd`
- installs boot restore service `pfwd-restore.service`
- creates state directory `/etc/pfwd`

## Fastest Way To Use (Menu)
Just run:

```bash
sudo pfwd
```

Then:
1. Select `1) Quick Add Forward`
2. Protocol default is `both` (TCP+UDP)
3. Enter incoming listen IP (default `0.0.0.0`)
4. Enter ports/mappings (comma-separated), examples:
   - `8080,2020,3030` means `8080->8080`, `2020->2020`, `3030->3030`
   - `8080:9090,2020:3030` means `8080->9090`, `2020->3030`
5. Enter one destination IP (used for all mappings)
6. Use `2) List Forwards` to confirm

## Forward One Port (CLI example)
Example: forward server port `443` to destination `10.10.10.20:8443`:

```bash
sudo pfwd add --proto tcp --listen 0.0.0.0:443 --to 10.10.10.20:8443 --name web443
sudo pfwd list
sudo pfwd status
```

## Common Commands
```bash
sudo pfwd                 # open interactive menu
sudo pfwd list            # show current forwards
sudo pfwd show 1          # show details of rule id 1
sudo pfwd update 1 --to 10.10.10.99:8443
sudo pfwd disable 1
sudo pfwd enable 1
sudo pfwd remove 1
```

## Performance
- `pfwd` is not a daemon; it runs only when you execute a command.
- Forwarding happens in kernel via `iptables` rules.
- Default profile is optimized for low overhead:
  - public-interface matching enabled
  - automatic fixed SNAT when safe

Show or change performance profile:

```bash
sudo pfwd perf show
sudo pfwd perf set --match-pub-iface 1 --snat-mode auto --snat-ip ""
```

## Full Command Reference
```bash
pfwd [--dry-run] [--json] <command> [args]
pfwd
```

Commands:
- `init`
- `perf show`
- `perf set [--match-pub-iface 0|1] [--snat-mode auto|snat|masquerade] [--snat-ip IP]`
- `add [--proto tcp|udp|both] --listen IP:PORT --to IP:PORT [--name NAME] [--enable|--disable]`
- `list`
- `show <id>`
- `update <id> [--proto tcp|udp|both] [--listen IP:PORT] [--to IP:PORT] [--name NAME] [--enable|--disable]`
- `remove <id>`
- `enable <id>`
- `disable <id>`
- `apply`
- `status`
- `flush --managed-only [--purge-state]`
- `export [file]`
- `import <file>`
