# Lumastra Discord RPC

A macOS and Windows tray app that shows what you're playing on your self-hosted
[Lumastra](https://github.com/Sapd/lumastra) server in your Discord status.

It reads your active sessions from the server, so it reflects playback **wherever it
happens** — browser, tvOS, phone. Movies, series, music, audiobooks and Live TV, each
individually toggleable.

## What it sends to Discord

While something is playing: the **title, episode or artist details, playback position and
duration, and an artwork URL**. Discord shows that on your public profile and fetches the
artwork from its own servers.

It only broadcasts **your own** sessions — never another user's, even on a shared server
where you can see other people's activity. If it can't confirm which account it's signed
in as, it broadcasts nothing rather than guessing.

Presence clears when playback stops. **Pause presence** in the tray menu stops
broadcasting immediately without signing out.

## Requirements

- A Lumastra server you can sign in to.
- The **Discord desktop app** running on the same machine — the web client doesn't expose
  the local socket Rich Presence needs.

## Install

Download from [Releases](https://github.com/Sapd/lumastra-discord-rpc/releases):

- **macOS** — `.dmg`
- **Windows** — `.msi` or `-setup.exe` to install, or `-portable-x64.exe` to just run it
  without installing (it still keeps its settings in `%APPDATA%`).

On Windows you'll get a SmartScreen warning, because the builds aren't code-signed yet —
click **More info** → **Run anyway**.

## Use

The app is tray-only: no dock icon on macOS, no taskbar button on Windows. Open its menu
from the tray icon — left-click on macOS, right-click on Windows.

- **Settings…** — server URL, sign in, and which media types to broadcast. Closing the
  window hides it rather than quitting.
- **Pause presence** — stop broadcasting without signing out.
- **Quit** — exit.

To sign in, enter your server URL and click **Sign in**. Your browser opens to approve the
device; if it doesn't open, the window shows the code and URL to enter manually.

The top line of the tray menu shows current status — signed out, paused, what's playing,
or why nothing is being sent.

## Building from source

See [BUILDING.md](./BUILDING.md).

## License

MIT, see [LICENSE](./LICENSE).
