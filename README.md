# Packet Storm Challenge

Submission for the packet storm challenge, optimized for execution time. Analyses the 1,000,000 packets in <60ms on my laptop.

## Usage

### Building

```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

The `RUSTFLAGS` environment variable is optional but may improve performance.

### Running

```
Usage: packet-storm [OPTIONS] <INPUT_FILE>

Arguments:
  <INPUT_FILE>

Options:
  -a, --all-ips
  -o, --out-file <OUT_FILE>
  -h, --help                 Print help
  -V, --version              Print version
```

By default the tool will print the top 5 primary targets to stdout. If you wish to print all targets, use the `-a` flag. Since printing so many lines to the terminal is quite slow, it is recommended to use `-o` when using `-a` so that the performance hit isn't terrible.

```
> .\target\release\packet-storm.exe .\packet-storm.pcap
Average packet size: 147.26 bytes
Total volume: 147258908 bytes

Primary targets:
        229.154.57.192  (17 packets recieved)
        86.213.243.19   (16 packets recieved)
        13.40.26.174    (16 packets recieved)
        62.36.30.144    (16 packets recieved)
        215.96.44.170   (16 packets recieved)

Protocols:
        UDP   : 59163
        TCP   : 940837
        Other : 0
```

### Benchmarking

Using hyperfine (`cargo install hyperfine`):

```
> hyperfine ".\target\release\packet-storm.exe .\packet-storm.pcap"
Benchmark 1: .\target\release\packet-storm.exe .\packet-storm.pcap
  Time (mean ± σ):      59.8 ms ±   2.8 ms    [User: 28.2 ms, System: 21.2 ms]
  Range (min … max):    57.1 ms …  68.2 ms    40 runs
```

## Additional notes on performance

- There were a couple of things I tried to increase perfomance. The main candidate was multithreading, but it was hard to justify the additional overhead created by threads. Because of the drawbacks of `.pcap` files, it's hard to split up the work for multiple threads ahead of time. Instead we need to read the file packet per packet, and since the work per packet is so minimal, it wasn't worth it to analyze the packet in another thread. As it stands the tool is single-threaded. 

- Some other strategies I tried were creating a custom hashmap implementation (with a simple ip hash function indexing into a Vec, with linear probing), but it was simpler and more idiomatic to create a custom `Hasher` instead, using `hashbrown`'s HashMap implementation. The hash is pretty much equivalent to a no-hash and as such faster than `rustc-hash`.

- I/O is a significant part of the runtime. It could be faster to `mmap` the input file so that reads are quicker when the same file is used as input multiple times, which would show up as performance gains during benchmarks but is a bit disingenuous in my opinion. 

- IPv6 addresses are not implemented, but it would be straightforward to hash these in the same way as IPv4 addresses.