# SHA-1 collision fixture

`shattered-1-prefix.bin` is the first 320 bytes of `shattered-1.pdf`, the
first public SHA-1 collision (SHAttered, Stevens, Bursztein, Karpman,
Albertini, Markov, 2017; https://shattered.io). The 192-byte prefix is
followed by the two near-collision blocks, so the collision detection in
`sha1-checked` flags it. It is the same file as in the RustCrypto
`sha1-checked` 0.10.0 test data (`tests/data/shattered-1.pdf`), truncated:

```sh
head -c 320 shattered-1.pdf > shattered-1-prefix.bin
# sha1: f92d74e3874587aaf443d1db961d4e26dde13e9c, the same as the first
# 320 bytes of shattered-2.pdf, which differ from these at byte 193.
```
