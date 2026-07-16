# KubeGuard — demo & recording guide

A ~3-minute narrated walkthrough of KubeGuard's **detect → chain → harden**
loop against an intentionally vulnerable payments workload.

Two ways to produce the video: an **AI-narrated visual player** (zero setup) and
a **real live-terminal** recording (genuine `kubeguard` output on camera).

---

## Option A — the AI-narrated visual player (fastest)

`demo-player.html` is a self-contained, animated CLI demo with AI voice-over.
Open it in a browser and it types the commands, streams the (real, captured)
outputs, shows a synced caption per beat, narrates each step aloud, and opens/
closes on branded title cards. Nothing to install, no cluster, no binary.

```
Open demo/video/demo-player.html in Microsoft Edge  (best neural voices),
click "Play with voice-over".
```

To make the video: press **F11** (fullscreen), start your screen recorder with
**desktop audio** enabled, then hit Play. Controls: **Space** pause/resume,
**R** restart, **Esc** menu. Pick a "Microsoft … Online (Natural)" voice from
the dropdown before playing — they sound far better than the built-in ones.

**The five beats** (every line of output is real, from `kubeguard` against
`test/fixtures/vulnerable.yaml`):

| Beat | Command | The point on screen |
|------|---------|---------------------|
| 1 · Detect | `kubeguard scan -i vulnerable.yaml` | 21 findings, 4 critical |
| 2 · Chain  | (same scan) | one **ATT&CK-tagged attack path**: checkout → cluster-admin, 6 hops with T-numbers |
| 3 · Prioritize | (same scan) | deterministic, **explainable** risk scores — the fix-first list |
| 4 · Harden | `kubeguard harden -o ./bundle` → re-scan | writes a least-privilege bundle; re-scan → **No findings** |
| 5 · Prove | `--fail-on high` | 12 compliance frameworks incl. **GCC: NCA ECC-1, NCA CCC, SAMA CSF, UAE NESA** (honest denominators) + a **non-zero CI exit** that blocks the PR |

Beat 2 is the money shot — most scanners list findings; KubeGuard *chains* them
into a single narrated attack path an executive immediately understands.

**Narration assets** (single source of truth = the player):

- `narration.txt` — the voice-over script (the player reads these same lines).
- `narration.mp3` (~2 MB) / `narration.wav` (~6 MB) — TTS render for use as a
  scratch track, to hand to a professional VO artist, or to mux under a silent
  screen capture. Embed the MP3; the WAV is the lossless source.

Regenerate the audio after editing the script (Windows PowerShell):

```powershell
Add-Type -AssemblyName System.Speech
$s = New-Object System.Speech.Synthesis.SpeechSynthesizer
$s.SetOutputToWaveFile("demo/video/narration.wav")
$b = New-Object System.Speech.Synthesis.PromptBuilder
Get-Content demo/video/narration.txt | % { $b.AppendText($_); $b.AppendBreak("Large") }
$s.Speak($b); $s.Dispose()
```

## Option B — real live terminal (for the Briefing itself)

No cluster needed — KubeGuard is offline and read-only, so a single binary and
the in-repo fixture reproduce every beat live:

```sh
go build -o kubeguard ./cmd/kubeguard          # kubeguard.exe on Windows

# Beat 1–3 — detect, chain, prioritize (one command shows all three):
./kubeguard scan -i test/fixtures/vulnerable.yaml

# Beat 4 — harden → re-scan → zero:
./kubeguard harden -o ./bundle
./kubeguard scan -i ./bundle                   # → "No findings."

# Beat 5 — the CI gate fails the build:
./kubeguard scan -i test/fixtures/vulnerable.yaml --fail-on high ; echo "exit=$?"   # exit=2
```

Record at 1080p with a large terminal font (≥18pt) so the attack-path hops and
the T-numbers are legible on a projector. Narrate over it using the beat scripts
in `narration.txt`.

## Recording tips

- **macOS:** QuickTime / ⌘⇧5. **Linux:** OBS / SimpleScreenRecorder.
  **Windows:** OBS or Xbox Game Bar (`Win+G`); use Windows Terminal.
- Upload unlisted to YouTube; that link is your Black Hat CFP video sample.
- Convert the WAV to a smaller MP3 if you have ffmpeg: `ffmpeg -i narration.wav narration.mp3`.

## A note on honesty (KubeGuard practices what it preaches)

The compliance mapping is labelled **indicative — not a certification or audit**,
exactly as KubeGuard prints it. The scores are **deterministic and explainable**
(every point is itemized), not an opaque model. The demo scans a fixture that
ships in the repo, so anyone can reproduce every number in this video.
