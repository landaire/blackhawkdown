# blackhawkdown

Make sure rust nightly is installed (`rustup install nightly && rustup default nightly`).

## Usage

```
cargo run --release -- <PATH_TO_DUMP> <PATH_TO_OUTPUT_DIR>
```


Output directory must exist.

## Supported Scanners

- XEX2 files
- STFS content packages
- Bink video files
- Deleted FATX file entries

Currently only deleted FATX file entries and Bink files will be extracted when scanning for content. 
