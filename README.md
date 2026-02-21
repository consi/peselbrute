# peselbrute

A high-performance brute-force tool for cracking encrypted ZIP and PDF files where the password is a Polish [PESEL](https://en.wikipedia.org/wiki/PESEL) number.

## Background

PESEL (Powszechny Elektroniczny System Ewidencji Ludności) is the Polish national identification number. It encodes the holder's date of birth and a serial number, making the password space predictable and enumerable - a PESEL-protected ZIP is far weaker than it appears. I created this tool to demonstrate the security risks of using PESEL as a password, which is a common practice in Poland. It takes around few seconds to crack the password on a modern machine in the worst case scenario.

## How it works

`peselbrute` generates every valid PESEL for birth dates in a given range (default: 1900 to today) and tries each one as the file password. You can narrow the search with `-from`, `-to`, and `-sex` flags. The tool auto-detects ZIP vs PDF from file signature and uses one of these strategies:

- **ZipCrypto fast path** - parses the raw ZIP local file header, reconstructs the ZipCrypto key stream, and filters candidates without decompressing most of them. This is the default when the ZIP uses the standard ZipCrypto (method ≠ 99) encryption.
- **ZIP library path** - falls back to the [yeka/zip](https://github.com/yeka/zip) library for non-standard or AES-encrypted entries.
- **PDF Standard fast path** - parses the PDF trailer/encryption dictionary once and validates candidates in-process for `/Filter /Standard` (R=2..6).

Candidates are searched outward from the middle of the date range toward both ends simultaneously, so central (statistically likely) birth years are tried first.

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
peselbrute [flags] <file.{zip|pdf}>
```

| Flag | Description | Default |
|------|-------------|---------|
| `-from` | Start of birth date range (YYYY-MM-DD) | `1900-01-01` |
| `-to` | End of birth date range (YYYY-MM-DD) | today |
| `-sex` | Filter by sex: `m` (male) or `f` (female) | both |
| `-workers` | Number of parallel workers | number of CPUs |
| `-bench` | Benchmark mode: run for duration and exit (e.g. `5s`, `1m`) | disabled |

### Examples

```bash
# Crack with default settings (all PESELs from 1900 to today)
./peselbrute secret.zip

# Narrow to a known birth date range
./peselbrute -from 1980-01-01 -to 1989-12-31 secret.pdf

# Search only male PESELs born in October 1980
./peselbrute -from 1980-10-01 -to 1980-10-31 -sex m secret.pdf
```

## Performance

The ZIP ZipCrypto fast path is CPU-bound and can be extremely fast. The PDF `/Filter /Standard` path is also CPU-bound, but for `/R>=3` it requires 20 RC4 passes per candidate (per the PDF spec), so it is much slower in practice.

| Mode | Typical speed |
|------|--------------|
| ZIP ZipCrypto fast | 100–500 M/s |
| ZIP library fallback | 0.2–1 M/s |
| PDF Standard fast (R=2..4) | 0.2–2 M/s |
| PDF Standard fast (R=5..6) | 10k–50k/s |

The entire PESEL space (~460 M candidates for 1900–2026) is typically exhausted in under 5 seconds on the fast path.

### Benchmarking

Use `-bench` to measure throughput without waiting for the password to be found:

```bash
./peselbrute -bench 10s test.pdf
```

Sample result on `test.pdf` (8 workers):

```
File:    test.pdf (PDF)
Mode:    PDF Standard R=6 AES-256
Workers: 8
Search:  ~460.7M candidates (1900-2026-02-20, from 1990 outward)

Benchmark: 10s | Checked: 3630000 | Speed: 0.4M/s
```

## Requirements

- Go 1.21+

## License

MIT
