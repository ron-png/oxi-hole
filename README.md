# oxi-hole

> [!WARNING]
> This DNS server is currently in its early alpha stages. It is under active development and may be unstable. Do not use in production environments.

## Installation

You can install Oxi-Hole easily using the provided installation script:

```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh
```

### Installation Options

The installation script accepts the following flags. You must pass them to `sh` using `-s -- `:

- `-c <channel>`: Choose the release channel (`stable` [default], `beta`, or `edge`).
- `-r`: Reinstall (overwrites an existing installation).
- `-v`: Enable verbose output.
- `-h`: Show the installer's help message.
- `-u`: Uninstall Oxi-Hole.

Example using flags (verbose install from the beta channel):
```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- -v -c beta
```

## Uninstallation

To completely remove Oxi-Hole from your system, run the script with the `-u` flag:

```bash
curl -s -S -L "https://raw.githubusercontent.com/ron-png/oxi-hole/master/scripts/install.sh?v=$(date +%s)" | sh -s -- -u
```
