# pbech32

[Bech32][] encoding and decoding library.

Links:

- [pbech32 package on crates.io][crates-io-pbech32]
- [pbech32 API Documentation on docs.rs][docs-rs-pbech32]

## What is Bech32?

[Bech32][] is a fast and user-friendly [base 32][] encoding format
that includes a [namespace][] and [checksum][].  [Bech32m][] is an
update to [Bech32][] with an improved [checksum][] algorithm.

A [Bech32][] string contains a human-readable part (HRP), an encoded
data part, and a 6 character [checksum][].  The data part and
[checksum][] are [base 32][]-encoded with a user-friendly
[alphabet][] that only contains lowercase [ASCII][] alphanumeric
characters.

Here is an example [Bech32m][] string:

```text
hello1vehkc6mn27xpct
```

[Bech32][] and [Bech32m][] are specified in [BIP173][] and [BIP350][],
respectively.

## Library Features

- [Bech32 (BIP173)][bip173] and [Bech32m (BIP350)][bip350] support.
- Idiomatic encoding and decoding via the [`Display`][display] and
  [`FromStr`][fromstr] traits.
- Decode arbitrarily long strings.
- Streamed, allocation-free encoding to any [writer][].
- No external dependencies.

## Examples

Decode from string:

```rust
use pbech32::Bech32;

let s = "a1qypqxpq9mqr2hj"; // bech32m-encoded string
let got: Bech32 = s.parse()?; // decode string

assert_eq!(got.hrp.to_string(), "a"); // check human-readable part
assert_eq!(got.data, vec![1, 2, 3, 4, 5]); // check data
```

Encode to string:

```rust
use pbech32::{Bech32, Hrp, Scheme};

let scheme = Scheme::Bech32m; // checksum scheme
let hrp: Hrp = "a".parse()?; // human-readable part
let data = vec![1, 2, 3, 4, 5]; // data
let got = Bech32 { scheme, hrp, data }.to_string(); // encode as string

assert_eq!(got, "a1qypqxpq9mqr2hj"); // check result
```

Decoding a string verifies the [checksum][] to catch mistakes:

```rust
use pbech32::{Bech32, Err};

let s = "a1wypqxpq9mqr2hj"; // string with error ("q" changed to "w")
let got = s.parse::<Bech32>(); // try to decode string

assert_eq!(got, Err(Err::InvalidChecksum)); // check result
```

Encode to a [writer][]:

```rust
use std::io::Write;
use pbech32::{Encoder, Hrp, Scheme};

let mut vec: Vec<u8> = Vec::new(); // output vector
let hrp: Hrp = "hello".parse()?; // human readable part

{
  let mut encoder = Encoder::new(&mut vec, Scheme::Bech32m, hrp)?; // create encoder
  encoder.write_all(b"folks")?; // write data
  encoder.flush()?; // flush encoder (RECOMMENDED)
}

let got = str::from_utf8(vec.as_ref())?; // convert output vector to string
assert_eq!(got, "hello1vehkc6mn27xpct"); // check result
```

Many error variants have a context field which provides additional
information about the error. Try to decode a string which has an invalid
character at position 1:

```rust
use pbech32::{Bech32, Err};

let s = "a 1xxxxxx"; // string with invalid character at position 1
assert_eq!(s.parse::<Bech32>(), Err(Err::InvalidChar(1))); // check result
```

More examples are available in [`examples/`][examples].

## Install

[pbech32 package page on crates.io][crates-io-pbech32]

Run `cargo add pbech32` to add [pbech32][] as a dependency to an
exiting [Rust][] project:

```sh
$ cargo add pbech32
```

Run `cargo install pbech32` to install the `bech32` tool:

```sh
# install bech32 tool in cargo bin dir (e.g. `~/.cargo/bin`)
$ cargo install pbech32
```

## Build

Run `cargo build` to create a debug build of the `bech32` tool in
`target/debug/`:

```sh
$ cargo build
...
$ echo -n hello | target/debug/bech32 encode; echo
example1dpjkcmr0qp8pe8
```

Run `cargo build --release` to create a release build of the `bech32`
tool in `target/release/`:

```sh
$ cargo build --release
...
$ echo -n 'hi there' | target/release/bech32 encode; echo
example1dp5jqargv4ex2at7pqx
```

You can also build the `bech32` tool in a container using
[Podman][] or [Docker][] like this:

```sh
$ podman run --rm -t -v "$PWD":/src -w /src docker.io/rust cargo build --release
...
$ echo -n foobarbaz | target/release/bech32 encode; echo
example1vehk7cnpwf3xz7sfaj6vp
```

To build a static binary of the example `bech32` tool in a container:

```sh
$ podman run --rm -it -v "$PWD":/src -w /src rust sh -c "rustup target add $(arch)-unknown-linux-musl && cargo build --release --target $(arch)-unknown-linux-musl"
...
$ ldd target/x86_64-unknown-linux-musl/release/bech32
        statically linked
$ du -sh target/x86_64-unknown-linux-musl/release/bech32
580K    target/x86_64-unknown-linux-musl/release/bech32
$ echo -n hello | target/x86_64-unknown-linux-musl/release/bech32 encode; echo
example1dpjkcmr0qp8pe8
```

## Documentation

[pbech32 API documentation on docs.rs][docs-rs-pbech32]

Run `cargo doc` to build the [API][] documentation locally in
`target/doc/pbech32/`:

```sh
$ cargo doc
...
$ ls target/doc/pbech32/index.html
target/doc/pbech32/index.html
```

Run `cargo doc --lib` build the library documentation and exclude the
`bech32` tool documentation:

```sh
# remove generated docs
# (needed to clean up stale artifacts)
$ cargo clean --doc

# generate library-only docs
$ cargo doc --lib
```

## Tests

Use `cargo test` to run the test suite:

```sh
$ cargo test
...
test result: ok. 46 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

all doctests ran in 0.23s; merged doctests compilation took 0.22s
```

Use `cargo clippy` to run the [linter][]:

```sh
$ cargo clippy
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.04s
```

Install [cargo-tarpaulin][] and use `cargo tarpaulin` to check code
coverage:

```sh
$ cargo tarpaulin --engine llvm
...
2026-03-27T03:46:05.799963Z  INFO cargo_tarpaulin::report: Coverage Results:
|| Uncovered Lines:
|| src/bin/bech32.rs: 113-116, 119, 124, 126, 161, 206-209
|| src/lib.rs: 811
|| Tested/Total Lines:
|| src/bin/bech32.rs: 28/40 +0.00%
|| src/lib.rs: 196/197 +0.00%
||
94.51% coverage, 224/237 lines covered, +0.00% change in coverage
```

**Note:** Some of the tests in `src/bin/bech32.rs` are ignored by
default because the tests set environment variables which will cause
tests in other threads to fail sporadically.

You can run the tests in a single thread and enable the ignored tests
like this:

```sh
$ cargo tarpaulin --engine llvm -j1 -i
2026-03-27T03:46:30.385793Z  INFO cargo_tarpaulin::report: Coverage Results:
|| Uncovered Lines:
|| src/bin/bech32.rs: 119, 126, 161, 206-209
|| src/lib.rs: 811
|| Tested/Total Lines:
|| src/bin/bech32.rs: 33/40 +12.50%
|| src/lib.rs: 196/197 +0.00%
||
96.62% coverage, 229/237 lines covered, +2.11% change in coverage
```

[bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  "Bech32 (BIP173)"
[bech32m]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  "Bech32m (BIP350)"
[bip173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
  "BIP173 (Bech32)"
[bip350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
  "BIP350 (Bech32m)"
[ascii]: https://en.wikipedia.org/wiki/ASCII
  "ASCII (Wikipedia)"
[base 32]: https://en.wikipedia.org/wiki/Base32
  "Base 32 (Wikipedia)"
[checksum]: https://en.wikipedia.org/wiki/Checksum
  "Checksum (Wikipedia)"
[namespace]: https://en.wikipedia.org/wiki/Namespace
  "Namespace (Wikipedia)"
[bch code]: https://en.wikipedia.org/wiki/BCH_code
  "BCH code (Wikipedia)"
[alphabet]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32
  "BIP173: Specification: Bech32"
[writer]: https://doc.rust-lang.org/std/io/trait.Write.html
  "writer"
[age encryption]: https://age-encryption.org/
  "age encryption"
[html]: https://en.wikipedia.org/wiki/HTML
  "HyperText Markup Language"
[rust]: https://rust-lang.org/
  "Rust programming language."
[git repository]: https://github.com/pablotron/pbech32
  "pbech32 git repository"
[pbech32]: https://github.com/pablotron/pbech32
  "pbech32 Rust library"
[cargo]: https://doc.rust-lang.org/cargo/
  "Rust package manager"
[podman]: https://podman.io/
  "Podman container management tool"
[docker]: https://docker.com/
  "Docker container management tool"
[api]: https://en.wikipedia.org/wiki/API
  "Application Programming Interface (API)"
[linter]: https://en.wikipedia.org/wiki/Lint_(software)
  "Static code analysis tool to catch common mistakes"
[crates.io]: https://crates.io/
  "Rust package registry"
[docs-rs-pbech32]: https://docs.rs/pbech32
  "pbech32 API documentation on docs.rs"
[crates-io-pbech32]: https://crates.io/crates/pbech32
  "pbech32 on crates.io"
[examples]: examples/
  "pbech32 examples/ directory"
[cargo-tarpaulin]: https://crates.io/crates/cargo-tarpaulin
  "Tarpaulin code coverage reporting tool."
[display]: https://doc.rust-lang.org/std/fmt/trait.Display.html
  "std::fmt::Display trait"
[fromstr]: https://doc.rust-lang.org/std/str/trait.FromStr.html
  "std::str::FromStr trait"
