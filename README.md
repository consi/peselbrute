# peselbrute

A high-performance brute-force tool for cracking encrypted ZIP and PDF files where the password is a Polish [PESEL](https://en.wikipedia.org/wiki/PESEL) number.

## Background

PESEL (Powszechny Elektroniczny System Ewidencji Ludności) is the Polish national identification number. It encodes the holder's date of birth and a serial number, making the password space predictable and enumerable - a PESEL-protected ZIP is far weaker than it appears. I created this tool to demonstrate the security risks of using PESEL as a password, which is a common practice in Poland. It takes around few seconds to crack the password on a modern machine in the worst case scenario.

## How it works

`peselbrute` generates every valid PESEL for birth dates from 1900 to today and tries each one as the file password. The tool auto-detects ZIP vs PDF from file signature and uses one of these strategies:

- **ZipCrypto fast path** - parses the raw ZIP local file header, reconstructs the ZipCrypto key stream, and filters candidates without decompressing most of them. This is the default when the ZIP uses the standard ZipCrypto (method ≠ 99) encryption.
- **ZIP library path** - falls back to the [yeka/zip](https://github.com/yeka/zip) library for non-standard or AES-encrypted entries.
- **PDF Standard fast path** - parses the PDF trailer/encryption dictionary once and validates candidates in-process for `/Filter /Standard` (R=2..4).

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
peselbrute [flags] <file.{zip|pdf}>
```

**Example:**

```
$ peselbrute secret.zip
File:    secret.zip (ZIP, 1 entries)
Entry:   document.pdf (204800 bytes)
Mode:    ZIP ZipCrypto (fast)
Workers: 10
Search:  ~459M candidates (1900-2026-02-20, from 1977 outward)
  Checked: 37M | Speed: 142.3M/s | Elapsed: 0.3s

*** PASSWORD FOUND: 77031512345 ***
Time: 312ms | Checked: 37450000
```

## Performance

The ZIP ZipCrypto fast path is CPU-bound and can be extremely fast. The PDF `/Filter /Standard` path is also CPU-bound, but for `/R>=3` it requires 20 RC4 passes per candidate (per the PDF spec), so it is much slower in practice.

| Mode | Typical speed |
|------|--------------|
| ZIP ZipCrypto fast | 100–500 M/s |
| PDF Standard fast | 0.2–2 M/s |
| ZIP library fallback | 1–3 M/s |

The entire PESEL space (~460 M candidates for 1900–2026) is typically exhausted in under 5 seconds on the fast path.

### Benchmarking

Use `-bench` to measure throughput without waiting for the password to be found:

```bash
./peselbrute -bench 10s test.pdf
```

Sample result on `test.pdf` (8 workers):

```
File:    test.pdf (PDF)
Mode:    PDF Standard (fast)
Workers: 8
Search:  ~460M candidates (1900-2026-02-20, from 1977 outward)

Benchmark: 10s | Checked: 3630000 | Speed: 0.4M/s
```

## Requirements

- Go 1.21+

## License

MIT
