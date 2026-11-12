# Crypt-in AI red team, August 2026: curated transcript

This repository holds the curated, redacted transcript of the AI red team that attacked
[Crypt-in](https://cryptin.lake8.dev/), our ESP32-S3 hardware encryption key, on 2–3 August 2026.

The public report with all the findings, fixes and errata is here:
**https://cryptin.lake8.dev/security/red-team-2026-08/**

The report is the summary. This repository holds the transcript behind it.

## What is in here

| File | What it is |
|---|---|
| `sessioni-2-e-3-trascrizione-curata.md` | One Claude Code conversation that contains report **Session 2** and **Session 3** (3 Aug 2026, 12:47–17:36 UTC). English header with a map of the key moments; the body is in Italian, the language the sessions were run in. |
| `f003_auto.py` | The agent's script for F-003: it parses the PIN from a USB capture, replays it and decrypts a whole file through the on-chip oracle, with no human interaction (6.73 s in the session). |
| `INDICE-trascrizioni.md` | Index of all five agent transcripts, with times and the mapping to the report's sessions. |

The red-team agent was **Claude Opus 5** in Claude Code, on a dedicated Windows VM, against a `-dev`
beta dongle with eFuses not burned (see the report's errata). A person, the "operator", steered it.

## What was removed, and why

- The test dongle's PIN, also in hex inside HID reports, shown as `<PIN>`.
- Licence JWTs, licence-server URLs and responses, keys, and long hex/base64 strings. They may be keys, seeds or tokens.
- Paths, user name and addresses of the host, and the name of a personal file of the operator used as a decryption target.
- The output of file reads and searches, because it is source code (not all of it public) or working reports.
- Claude Code metadata.

**What is not here:** the agent's internal reasoning. Claude Code stores those blocks empty, so they don't
exist in any version of the transcript. The other four transcripts and the raw files are not public.

Editorial notes added in November 2026 are marked `📝 [Nota editoriale, novembre 2026]`. The agent's own
words are never changed. One of the notes marks the moment the agent retracts a fix it had wrongly
reported as verified in Session 1 (14:14 UTC).

## Licence

- Transcript and index: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (`LICENSE-CC-BY-4.0.txt`).
- `f003_auto.py`: [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) (`LICENSE-Apache-2.0.txt`), like the
  [Crypt-in SDK](https://github.com/jaffa2970/cryptin-sdk-beta).

## Want to try yourself?

Crypt-in is in developer beta, and breaking it is allowed: https://cryptin.lake8.dev/

Limits:
- Windows only for setup.
- There is no bug bounty.
- The firmware and the licence server are closed source. The SDK and the app are open source.

Made by [lake8.dev](https://lake8.dev), Bologna.
