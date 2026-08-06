const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

// `show_deep_links` is intentionally absent — the config field exists but has
// no effect, so exposing it would be a lie. See the plan's Spec Coverage note.
const TOGGLES = [
  'enable_movies',
  'enable_series',
  'enable_music',
  'enable_audiobooks',
  'enable_livetv',
];

let config = null;

// Single place that reconciles the auth status text and the sign-in/sign-out
// buttons, so `load()`, the sign-in success path, and the sign-out handler
// can't drift out of sync with each other (that drift is what let "Signed
// in" and a still-visible Sign in button show at the same time).
function applyAuthState(signedIn) {
  document.getElementById('auth').textContent = signedIn ? 'Signed in' : 'Not signed in';
  document.getElementById('signin').classList.toggle('hidden', signedIn);
  document.getElementById('signout').classList.toggle('hidden', !signedIn);
}

async function load() {
  config = await invoke('get_config');
  document.getElementById('server_url').value = config.server_url ?? '';
  for (const key of TOGGLES) document.getElementById(key).checked = config[key];
  applyAuthState(await invoke('get_auth_status'));
}

// Returns whether the save actually persisted, so callers that depend on the
// server URL (sign-in) can bail out instead of proceeding with a value the
// backend just rejected.
async function save() {
  // Re-read the current on-disk config and merge the form fields into it,
  // rather than writing back the snapshot taken at load time. Otherwise a
  // pause toggled from the tray while this window is open would be
  // clobbered by the window's stale `paused` value on the next save.
  config = await invoke('get_config');
  config.server_url = document.getElementById('server_url').value.trim() || null;
  for (const key of TOGGLES) config[key] = document.getElementById(key).checked;

  const errorEl = document.getElementById('server_url_error');
  try {
    await invoke('save_config', { config });
    errorEl.textContent = '';
    return true;
  } catch (error) {
    // `save_config` rejects a URL that fails to parse or lacks an http(s)
    // scheme — surface it here immediately, rather than letting the app go
    // permanently, silently dead on the next poll.
    errorEl.textContent = error;
    return false;
  }
}

// Fired by `begin_login` as soon as the device code is obtained and the
// browser-open has been attempted — before the (potentially minutes-long)
// approval poll, not after. When the browser fails to open this is the
// user's only way to learn the code and URL; without it they would stare at
// "Waiting…" for the whole device-code lifetime with nothing to act on.
listen('device-code', (event) => {
  const { userCode, verificationUri, browserOpened } = event.payload;
  const status = document.getElementById('auth');
  status.textContent = browserOpened
    ? `Waiting for approval in your browser… (code ${userCode})`
    : `Open ${verificationUri} and enter code ${userCode}`;
});

document.getElementById('signin').addEventListener('click', async () => {
  if (!(await save())) return;
  const status = document.getElementById('auth');
  status.textContent = 'Starting sign-in…';
  try {
    // The device code returned here is already spent the moment approval
    // completes, so it's not shown — `applyAuthState` sets a plain "Signed
    // in" (or the not-persisted warning below). It was still useful earlier,
    // while approval was pending; that's the `device-code` listener above,
    // which is untouched.
    const { persisted } = await invoke('begin_login', { serverUrl: config.server_url });
    applyAuthState(true);
    if (!persisted) {
      // `persisted: false` means `begin_login` wrote the login but couldn't
      // read it back — on macOS that happens when the app isn't code-signed,
      // because the keychain entry it just wrote isn't readable by this
      // build. The sign-in worked for right now (it's cached in memory), so
      // this doesn't block anything — it just won't survive a restart.
      status.textContent =
        "Signed in, but this build can't save your login — you'll need to sign in again " +
        'after restarting the app, because it is not code-signed.';
    }
  } catch (error) {
    applyAuthState(false);
    status.textContent = `Sign-in failed: ${error}`;
  }
});

document.getElementById('signout').addEventListener('click', async () => {
  await invoke('logout');
  applyAuthState(false);
});

for (const key of TOGGLES) document.getElementById(key).addEventListener('change', save);
document.getElementById('server_url').addEventListener('change', save);

load();
