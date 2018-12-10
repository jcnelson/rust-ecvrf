# rust-ecvrf
ECVRF implementation with curve25519-dalek and Ristretto

# Build

```bash
$ cargo build
```

# Usage

```bash
$ rust-ecvrf secret
47553650386c84fd436282419d896ae1589112d73e15eaba0be36ec547a00e31
```

```bash
$ rust-ecvrf pubkey 47553650386c84fd436282419d896ae1589112d73e15eaba0be36ec547a00e31
015da05267e9187dcb362b736609bfb3d3d55c80829af8f258a49ff9770f2fe4
```

```bash
$ rust-ecvrf prove 47553650386c84fd436282419d896ae1589112d73e15eaba0be36ec547a00e31 "hello world"
904eedfe4973e2aa0eaaa8e58d30de0dd7c78816c3690c1c94f2554854daa22dd7dd6b89d2ebcbf6f36f4f773d6af446e18b66111f32762d76c5eb1d041730a59bdca34e141cbf887b630bcec701b008
```

```bash
$ PROOF="904eedfe4973e2aa0eaaa8e58d30de0dd7c78816c3690c1c94f2554854daa22dd7dd6b89d2ebcbf6f36f4f773d6af446e18b66111f32762d76c5eb1d041730a59bdca34e141cbf887b630bcec701b008"
$ PUBKEY="015da05267e9187dcb362b736609bfb3d3d55c80829af8f258a49ff9770f2fe4"
$ rust-ecvrf verify "$PUBKEY" "$PROOF" "hello world"
true
$ rust-ecvrf verify "$PUBKEY" "$PROOF" "nope"
false
```

