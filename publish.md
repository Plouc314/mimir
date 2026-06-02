# Publishing

Mimir is published to PyPI as [`mimir-vault`](https://pypi.org/project/mimir-vault/).

## Release steps

1. Bump `version` in `pyproject.toml` (PyPI rejects re-uploading an existing version).
2. Build the distributions (sdist + wheel into `dist/`):

   ```sh
   uv build
   ```

3. Upload to PyPI:

   ```sh
   uv publish
   ```

`uv build` writes to `dist/`; clean it between releases (`rm -rf dist/`) so `uv publish` doesn't try to re-upload stale builds.

## Authentication

PyPI uses an API token (create one at <https://pypi.org/manage/account/token/>, scoped to the
`mimir-vault` project). With token auth the username is `__token__` and the token is the password,
but `uv publish` handles that for you when given a token.

`uv publish` reads the token from **`UV_PUBLISH_TOKEN`** (or the `--token` flag).

```sh
# pass it explicitly
uv publish --token "$UV_PUBLISH_TOKEN"
```
