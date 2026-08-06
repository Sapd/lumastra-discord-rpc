# Building from source

## Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/)
- **Windows only:** the MSVC toolchain — Visual Studio Build Tools with the "Desktop
  development with C++" workload, or any Visual Studio install providing it. Note that
  installing Build Tools alongside an existing Visual Studio can fail with error 5002;
  if you already have Visual Studio with the C++ workload, you don't need Build Tools.
- **macOS only:** Xcode command line tools (`xcode-select --install`).

## Build and run

```bash
npm install
npm run tauri dev      # run in development
npm run tauri build    # produce an installer
```

## Tests and lints

```bash
cd src-tauri
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

`--all-targets` matters — without it, clippy doesn't lint test code at all.

Test counts differ slightly per platform: some tests are `#[cfg]`-gated to assert
platform-specific behaviour (file permissions on Unix, config-directory resolution per
OS), so each platform runs its own.

## Token storage

Release builds store OAuth tokens in the OS keychain (macOS Keychain, Windows Credential
Manager). **On macOS this only persists across launches if the app is signed with a stable
identity.** The Keychain ACL is bound to the code signature, and an ad-hoc (unsigned)
signature is derived from the binary's own hash — so an unsigned or ad-hoc-signed release
build can write a token, report success, and still be unable to read it back on the next
launch, or on the next run at all. That is why debug builds use a file store instead (see
below), and it applies just as much to release builds until
[signing is actually configured](#releases-and-signing) — an unsigned release quietly loses
the login on every restart.

Debug builds deliberately do **not** use the keychain. They use a `0600` file in the app
config directory instead, because development binaries are ad-hoc signed — their code
signature changes on every rebuild, so macOS can't maintain a stable keychain ACL and
re-prompts on every launch.

## Discord Rich Presence art asset

The Discord application backing `DISCORD_APP_ID`
([`src-tauri/src/presence/client.rs`](src-tauri/src/presence/client.rs)) needs an image
uploaded to its **Rich Presence → Art Assets** with the key `lumastra` (see
`FALLBACK_ASSET_KEY` in [`src-tauri/src/mapper/mod.rs`](src-tauri/src/mapper/mod.rs)).

That's the fallback shown when an item has no usable public artwork URL. Without it, such
items render with no image rather than failing outright.

Note the asset list is separate from the *Cover Image* slot higher up the same page — the
cover image is for chat invites and won't satisfy the asset key.

### Why artwork sometimes falls back

Discord fetches artwork from its own servers, so a Lumastra reachable only on a LAN or
over a VPN can't serve item artwork to Discord. The server supplies a public CDN URL where
it can derive one (from TMDB, falling back to the series poster for episodes); this asset
covers everything else.

## Releases and signing

Tagging `v*` triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds a universal macOS `.dmg` and a Windows x86_64 `.msi` and opens a draft
release.

**macOS** builds are signed and notarized when these repository secrets are set:
`APPLE_CERTIFICATE`, `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD`, `APPLE_TEAM_ID`. Without them the build still succeeds but produces an
unsigned, unnotarized `.dmg` — it doesn't fail, so check the artifact if you expect it
signed.

**Windows** builds are unsigned. There's no free publicly-trusted Windows code-signing
certificate — since June 2023 the keys must live on FIPS 140-2 hardware. The
[SignPath Foundation](https://signpath.org/) signs open-source projects for free and this
project would qualify (MIT, no dual-licensing, no proprietary components), but it requires
an existing public release to point at and hasn't been set up.

Note that an OV certificate doesn't grant instant SmartScreen reputation — that accrues
with download volume. Only EV certificates bypass it immediately.
