# OpenBack community plugins

Free, open-source plugins for OpenBack written by the community: integrations, LogicBlock libraries, function
templates and ready-made projects and apps. OpenBack reads this repository's catalog (`index.json`, signed:
`index.json.sig`) and downloads the archives under `dist/`; the plugins appear in Settings > Integrations (Catalog,
Libraries, Templates, App) with a **Community** label. An official plugin with the same type and slug hides the community one.

License: each plugin's `license` in `index.json`; when a plugin has none, the repository's (GPL-3.0, see `LICENSE`).

## Layout

| Path | What |
|---|---|
| `repository.json` | channel, signing publisher id, default license |
| `categories.json` | the categories' labels (Italian, English) per plugin type |
| `plugins/integrations/<slug>/` | an integration package (OpenBack Integration SDK): `manifest.json`, `integration.py`, `doc/` |
| `plugins/serverless-function-libraries/<slug>/` | a serverless function (LogicBlock) library: `manifest.json`, `library.py`, `doc/` |
| `plugins/templates/<slug>/` | a function template: `template.json`, `doc/` |
| `plugins/apps/<slug>/` | a ready-made project or app: a scope bundle exported from OpenBack, unzipped (`bundle.json`, `sections/`, `data/`), `doc/` |
| `plugins/<type>/<slug>/plugin.json` | optional catalog data: `license`, `tags`, `requires.plugins` |
| `dist/<type>/<slug>/` | the published archives (`.obint`, `.oblib`, `.obtpl`, `.obapp`), never changed once published |
| `tools/build.py` | checks the plugins, packs new versions and signs `index.json` |
| `SDK/Auth/<platform>/<version>/` | the App authenticator SDKs and CMS plugins (`openback-app-auth-<platform>`), not part of the catalog: see [SDK/Auth](SDK/Auth/README.md) |

The SDKs carry their own license (MIT; the WordPress and Joomla plugins GPL-2.0-or-later), stated in each package's
`LICENSE`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Check your plugin locally with:

```
python tools/build.py --check
```

Maintainers publish with `python tools/build.py --key <community private key>`.
