# Crypt filename migration helper

This helper renames encrypted objects on the real backend from one Crypt
filename format to another through the OpenList HTTP API.

It is useful for migrating:

- rclone-compatible old names to the new stream names,
- the first stream implementation with fixed CTR IV to the final CRC32-IV stream names.

It only uses HTTP APIs:

1. `/api/admin/storage/list` finds the Crypt storage and its `remote_path`,
2. `/api/fs/list` recursively lists the real backend path,
3. `/api/fs/rename` renames each real backend object.

Run with dry-run first:

```bash
go run ./drivers/crypt/migrate_filename -config ./drivers/crypt/migrate_filename/config.json
```

For the fixed-IV stream version, set this under `old`:

```json
"legacy_stream_iv": true
```

`dry_run` defaults to `true`; set it to `false` only after the printed plan looks right.
