# Releasing StackPulse

Releases are tagged from a reviewed commit on `main`. Pushing the tag publishes
to crates.io and creates a GitHub release from the matching changelog entry.

## Prepare

1. Update `version` in `Cargo.toml` and refresh `Cargo.lock`.
2. Move the relevant entries under `## Unreleased` in `CHANGELOG.md` to
   `## X.Y.Z - YYYY-MM-DD`. Leave a fresh `## Unreleased` section above it.
3. Run the local checks and package dry run:

   ```bash
   make ci
   cargo publish --dry-run --locked
   ```

4. Open and merge a pull request. Wait for `Required checks`, `Coverage`, and
   `CodSpeed` on `main`.

## Publish

Create and push one annotated tag from the merged commit:

```bash
git switch main
git pull --ff-only
git tag -a vX.Y.Z -m "stackpulse X.Y.Z"
git push origin vX.Y.Z
```

The publish workflow checks the tag against `Cargo.toml`, verifies that the
commit belongs to `main`, reads a nonempty release entry from `CHANGELOG.md`,
and builds the packaged crate. crates.io trusted publishing authenticates the
workflow through the `release` environment. After publication, the workflow
creates the GitHub release from the same changelog entry.

## Verify

```bash
cargo info stackpulse
gh release view vX.Y.Z --repo pablogsal/stackpulse
```

Confirm that crates.io lists the intended version, the release tag points to
the merged commit, and the GitHub release notes match `CHANGELOG.md`.

If publication fails before crates.io accepts the crate, fix the repository,
environment, or crates.io configuration and rerun the workflow. A code change
requires a new version and tag. If crates.io accepted the version, publish a
patch release. Published crate versions are immutable.
