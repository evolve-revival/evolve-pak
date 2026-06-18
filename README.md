# evolve-pak

Command-line tool for inspecting, extracting, auditing, and repacking Evolve `.pak` (`.m2k`) archives.

## Pak format

Evolve pak files are ZIP archives where all entry data is encrypted with Twofish in CTR mode (little-endian 128-bit counter). Each file uses a unique key and IV stored in the ZIP End-of-Central-Directory comment as 16 RSA-1024 PKCS#1 OAEP-SHA256 encrypted blocks. The vanilla game ships with an embedded RSA-1024 public key; the revival project generates its own keypair to sign custom pak files.

The ZIP local file header is itself the first four encrypted bytes of the stream — there is no plaintext magic at byte 0. File data resets the CTR counter to the IV (it does not continue from the header stream).

## Commands

```
evolve-pak list <file.pak>
    List all entries with compressed size, uncompressed size, and path.

evolve-pak extract <file.pak> [outdir]
    Extract all entries. Defaults to a directory named after the pak file.

evolve-pak inspect <file.pak>
    Show pak header info (magic variant, file size).

evolve-pak audit <game-dir>
    Size breakdown across all pak files in a game directory.
      --contents, -c    Break down by file category inside each pak.

evolve-pak perf <game-dir>
    List the largest entries across all openable pak files.
      --top, -n N       Number of entries to show (default 20).

evolve-pak keygen
    Generate an RSA-1024 keypair (revival.priv, revival.pub).
      --out-dir <dir>   Output directory (default: current directory).
      --force           Overwrite existing key files.

evolve-pak pack <dir> <out.pak>
    Pack a directory into an encrypted pak file.
      --privkey <path>  Path to revival.priv (required).

evolve-pak rekey <game-dir>
    Validate or re-sign all pak EOCD comments with the revival key.
      --privkey <path>  Path to revival.priv (required with --in-place).
      --in-place        Write new EOCD comments back to the pak files.

evolve-pak keyfind <Evolve.exe> <any.pak>
    Scan Evolve.exe for the Twofish key that decrypts a given pak file.
```

## Build

Requires Go 1.21+.

```bash
go build -o evolve-pak ./cmd
```

## Examples

List a pak:

```bash
evolve-pak list Scripts.pak
```

Extract to a directory:

```bash
evolve-pak extract Scripts.pak ./out
```

Generate a revival keypair and rekey all game pak files:

```bash
evolve-pak keygen --out-dir ./keys
evolve-pak rekey /path/to/Evolve --privkey ./keys/revival.priv --in-place
```

Create a custom pak from a directory:

```bash
evolve-pak pack ./my-scripts custom.pak --privkey ./keys/revival.priv
```

After rekeying, place `revival.pub` and the `dbghelp.dll` injector in `bin64_SteamRetail/` so the game can verify the new signatures at load time.

## Related

- [injector](https://github.com/evolve-revival/injector) — dbghelp proxy that patches the vanilla RSA key in game memory at load time
