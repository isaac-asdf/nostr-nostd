# About

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]

This is a [nostr](https://github.com/nostr-protocol/nips) library written to support development of nostr clients running in an environment without the standard environment.
A demo project can be seen [here](https://github.com/isaac-asdf/esp32-nostr-client).

# Implemented

- Kinds implemented
  - ShortNote, 1
  - DMs, 4
  - Auth, 22242
  - IOT, 5732
- Tags on notes, limit of 5

# Future improvements

- Support more note kinds
- Investigate GenericArray to make length of content able to be larger without always filling memory

[//]: # "badges"
[crate-image]: https://buildstats.info/crate/nostr-nostd
[crate-link]: https://crates.io/crates/nostr-nostd
[docs-image]: https://docs.rs/nostr-nostd/badge.svg
[docs-link]: https://docs.rs/nostr-nostd/
[build-image]: https://github.com/isaac-asdf/nostr-nostd/actions/workflows/nostr-nostd.yml/badge.svg
[build-link]: https://github.com/isaac-asdf/nostr-nostd/actions/workflows/nostr-nostd.yml
