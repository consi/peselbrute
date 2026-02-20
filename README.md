# peselbrute

A high-performance brute-force tool for cracking ZipCrypto-encrypted ZIP files where the password is a Polish [PESEL](https://en.wikipedia.org/wiki/PESEL) number.

## Background

PESEL (Powszechny Elektroniczny System Ewidencji Ludności) is the Polish national identification number. It encodes the holder's date of birth and a serial number, making the password space predictable and enumerable — a PESEL-protected ZIP is far weaker than it appears. I created this tool to demonstrate the security risks of using PESEL as a password, which is a common practice in Poland. It takes around few seconds to crack the password on a modern machine in the worst case scenario.

## How it works

`peselbrute` generates every valid PESEL for birth dates from 1900 to today and tries each one as the ZIP password. It uses two strategies:

- **ZipCrypto fast path** — parses the raw ZIP local file header, reconstructs the ZipCrypto key stream, and filters candidates without decompressing most of them. This is the default when the ZIP uses the standard ZipCrypto (method ≠ 99) encryption.
- **Library path** — falls back to the [yeka/zip](https://github.com/yeka/zip) library for non-standard or AES-encrypted entries.

Candidates are searched outward from 1977 (a statistically likely birth year) toward both ends of the 1900–today range simultaneously, so common birth years are tried first.

All available CPU cores are used in parallel, typically achieving tens to hundreds of millions of candidates per second on modern hardware.

## Installation

### Pre-built binaries

Download the latest binary for your platform from the [Releases](../../releases) page.

### Build from source

Requires Go 1.21 or later.

```bash
git clone <repo-url>
cd peselbrute
go build -ldflags="-s -w" -o peselbrute .
```

Or use the Makefile:

```bash
make build
```

## Usage

```bash
peselbrute <zipfile>
```

**Example:**

```
$ peselbrute secret.zip
File:    secret.zip (1 entries)
Entry:   document.pdf (204800 bytes)
Mode:    ZipCrypto (fast)
Workers: 10
Search:  ~459M candidates (1900-2026-02-20, from 1977 outward)
  Checked: 37M | Speed: 142.3M/s | Elapsed: 0.3s

*** PASSWORD FOUND: 77031512345 ***
Time: 312ms | Checked: 37450000
```

## Performance

On a modern multi-core machine the fast ZipCrypto path reaches **100–500 M candidates/s**. The library fallback path is significantly slower (~1–5 M/s) because it fully decompresses and validates each candidate.

| Mode | Typical speed |
|------|--------------|
| ZipCrypto fast | 100–500 M/s |
| Library fallback | 1–5 M/s |

The entire PESEL space (~460 M candidates for 1900–2026) is typically exhausted in under 5 seconds on the fast path.

## Requirements

- Go 1.21+

## License

MIT
