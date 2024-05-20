# Hashit - A CLI Tool for Hashing Files and Strings

Hashit is a command-line tool that supports various hash functions for files and strings. It provides an easy way to compute hashes using algorithms like Adler-32, MD4, MD5, SHA-1, SHA-2, SHA-3, FNV, and CRC.

## Features

- Hash files and strings using multiple hash functions.
- Supports the following hash algorithms:
  - Adler-32
  - MD4
  - MD5
  - SHA-1
  - SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
  - SHA-3 (SHA-256, SHA-512, Shake128, Shake256)
  - FNV (FNV-1, FNV-1a, 32-bit and 64-bit variants)
  - CRC (CRC32, CRC64)

## Installation

### Via Go

Use Go to install the package for you.

```sh
go install github.com/TechMDW/hashit@latest
```

### Via github releases

You can download the latest binary from [here](https://github.com/TechMDW/hashit/releases/latest).

### Build it yourself

Clone the repository and build the binary

```sh
git clone https://github.com/TechMDW/hashit.git
cd hashit
go build -o hashit ./main.go
```

**PS**: For windows you wanna add the correct extensions, for example `.exe`.

## Usage

### Hash string

To hash a string, simply pass the string as an argument to the hashit binary:

```sh
hashit "hello world"
```

### Hash file

To hash a file, use the -f flag followed by the file path:

```sh
hashit -f /path/to/file
```

### Specify a Hash Algorithm

To use a specific hash algorithm, use the -t flag followed by the hash type:

```
./hashit "hello world" -t md5
./hashit -f /path/to/file -t sha256
```

### List Available Hash Functions

To list all available hash functions, use the list-hashes command:

```sh
./hashit list-hashes
```

### Help

To see the help information, use the --help flag:

```sh
./hashit --help
```

## Running test

To run the tests, use the following command:

```sh
go test ./...
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
