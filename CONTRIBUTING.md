# Contributing a plugin

1. Fork the repository and add your plugin in its folder: `plugins/integrations/<slug>/`,
   `plugins/serverless-function-libraries/<slug>/` or `plugins/templates/<slug>/`. The folder's name is the plugin's slug (the one in its manifest).
2. Write its documentation inside it: `doc/README.md` (what it does, how to configure it), plus one page per block
   (`doc/blocks/<name>.md`) for an integration or a library. It is shipped with the plugin and shown in OpenBack.
3. Add `plugin.json`:

   ```json
   {
     "license": "MIT",
     "tags": ["crm"],
     "author": "Your name",
     "homepage": "https://example.com",
     "requires": {"plugins": [{"type": "library", "slug": "data.xml"}]}
   }
   ```

   `license` is yours to choose (an SPDX id); without it the plugin is under this repository's license (GPL-3.0).
   `requires.plugins` lists the plugins yours needs (of this repository or of the official one): OpenBack installs them
   with it and removes them with it when nothing else needs them.
4. Check it: `pip install cryptography` and `python tools/build.py --check`. An integration is also checked with the
   OpenBack Integration SDK (`openback-integration validate plugins/integrations/<slug>`).
5. Open a pull request. The CI runs the same check.

## What each type needs

- **Integration**: an integration package made with the OpenBack Integration SDK (`manifest.json`, `integration.py`).
  The Python packages it imports must be ones OpenBack's integration-service already has.
- **Library**: `manifest.json` (`schema_version` 1, `slug`, `name`, `description`, `version`, `category`, `"publisher":
  "openback-community"`) and `library.py` with `BLOCKS = [LogicBlock classes]`, typed `lib.<slug>.<Name>`. Slugs of
  OpenBack's own libraries (`core`, `std.*`, `math.*`, `data.*`, ...) are reserved.
- **Template**: `template.json` (`schema_version` 1, `slug`, `version`, `level`, `category`, `product`, `name`,
  `description`, `steps`, `integrations`, `libraries`, `group_path`, and `build`: the new function's fields in Italian
  and English). The easiest start is an existing template of the official repository.

## Publishing (maintainers)

After merging, a maintainer packs the new versions and signs the catalog with the repository's key:

    python tools/build.py --key <community signing key (PEM)>
    git add -A && git commit && git push

A version, once in `dist/`, cannot change: raise the plugin's version to publish new content.
