# Publishing HAP v1.0.0 through the GitHub website

GitHub is a replaceable distribution channel, not protocol authority. This repository is finalised under the founder pseudonym **Horus**. Funding is optional and outside HAP protocol validity.

## Protect the account email

In GitHub **Settings → Emails**, enable:

- **Keep my email addresses private**
- **Block command line pushes that expose my email**

Web-created commits will use the privacy settings attached to the GitHub account.

## Create the repository without command-line tools

1. Create a new public repository named `history-anchor-protocol`.
2. Do not add a generated README, `.gitignore`, or licence because these files are already included.
3. Open **Add file → Upload files**.
4. Upload the contents of `UPLOAD_1_SOURCE_AND_DOCS` and commit them directly to `main` with the message `Publish History Anchor Protocol v1.0.0`.
5. Open **Add file → Upload files** again.
6. Upload the contents of `UPLOAD_2_TESTS` and commit them directly to `main` with the message `Add HAP v1.0.0 test suite`.

GitHub currently accepts up to 100 files in one browser upload, which is why the source is split into two batches.

## Repository settings before announcement

- Confirm `FUNDING.md`, `FUNDING_MANIFEST.json`, and `GENESIS_STATEMENT.md` show the same Bitcoin address.
- Enable private vulnerability reporting.
- Enable branch protection and require the test workflow after the initial upload.
- Do not enable anonymous public evidence uploads merely because the source is public.
- Read `LEGAL_BOUNDARIES.md` before operating a hosted relay, archive, search interface, or evidence service.

## Create the GitHub Release in the browser

1. Open **Releases → Draft a new release**.
2. Enter `v1.0.0` and choose **Create new tag on publish** targeting `main`.
3. Use the title `History Anchor Protocol v1.0.0`.
4. Copy the contents of `RELEASE_NOTES.md` into the release description.
5. Attach the wheel and its checksum from the separate `RELEASE_ASSETS` folder.
6. Publish the release.

GitHub will automatically provide source-code ZIP and TAR downloads for the tag. The release should be presented as a first public reference implementation for independent inspection and regtest/signet commissioning, not as software that cannot fail.
