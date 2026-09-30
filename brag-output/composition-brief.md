# Hyperframes Composition Brief: laya-phishield

## Objective
Create a short launch-style brag video for laya-phishield, an explainable
phishing detector built on the laya decision model.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 20 seconds

## Source Material
- Project root: `C:/Code Main/laya-phishield`
- Primary files read: `docs/how-it-works.html` (visual reference),
  `docs/assets/how-it-works-phish.png`, `docs/assets/how-it-works-legit.png`,
  `README.md`, `evals/results.json`
- Product name: laya-phishield
- Tagline / strongest claim: eight narrow questions, one verdict, every
  reason named
- Key UI or visual moment to recreate: the eight signal rows with mono
  labels and red-filled bars (stage 03 of docs/how-it-works.html), and the
  verdict card (stage 04: big mono score, pale pill, reasons list)
- Copy that must appear verbatim:
  - "one big question is the wrong question."
  - "URGENT: Your account has been limited"
  - "display name claims a brand it does not own"
  - "eight narrow questions, one forward pass."
  - "0.990" / "PHISHING" / "asks_credentials +2.56" / "urgency_pressure
    +1.86" / "external_link_risk +1.56"
  - "0.053" / "LEGITIMATE" / "Release notes 1.4.2"
  - "eight narrow questions, one verdict, every reason named."

## Creative Direction
- Tone preset: polished
- Creative direction: security product demo with quiet confidence,
  editorial typography, warm monochrome
- Interpretation: fewer scenes, longer holds; motion restrained and
  precise; the measured numbers are the spectacle. No neon, no gimmicks,
  generous whitespace, hairline borders.
- Angle: one email walks the gauntlet and every number on screen is real
  model output; then the same machine waves a legitimate email through.
- Hook: phishing subject types out, a "0.59" stamp rejects the wide
  question, the frame rebuilds into eight small questions.
- Outro / punchline: "eight narrow questions, one verdict, every reason
  named." with AUC 0.9531 and $0 per 1,000 emails.
- Avoid:
  - Generic SaaS language
  - Abstract filler visuals
  - Unrelated visual redesign

## Visual Identity
- Background: #FBFBFA
- Text: #111111 (ink), #787774 (muted)
- Accent: #9F2F2D on #FDEBEC (phishing), #346538 on #EDF3EC (legit),
  hairlines #EAEAEA, card surfaces #FFFFFF with 1px #EAEAEA borders and
  12px radius
- Display font: serif stack (Georgia, "Playfair Display", serif) with tight
  tracking for the hook/outro lines
- Body font: "Helvetica Neue", "Segoe UI", sans-serif; ALL data (scores,
  signal names, reasons) in ui-monospace, "Cascadia Mono", Consolas, monospace
- Visual references from the project: docs/how-it-works.html stage cards
  (faux-OS window chrome with three light-gray dots, pill chips, eight
  signal rows, verdict head with big score + pill + reasons)

## Storyboard
Use the storyboard in `brag-output/brag-plan.md` as the creative contract.

Scene summary:
1. The wrong question — 3.5s — typed subject, 0.59 stamp rejection, serif
   hook line
2. The pre-pass — 3s — chips pop one by one on beats
3. Eight narrow questions — 5.5s — signal bars fill on the beat grid with
   real values (0.92, 0.91, 0.86, 0.86, 0.22, 0.22, 0.22, 0.00)
4. The verdict — 4s — 0.990 PHISHING card + three reasons, beat-locked
5. The other side — 2.5s — legit run, all-dark bars, 0.053 LEGITIMATE
6. Outro — 1.5s — serif line + mono footer metrics

## Audio
- Audio role: warm bed with sparse professional accents
- Audio arc: typed tension -> methodical build -> single payoff swell ->
  green exhale -> soft close
- Music: happy-beats-business-moves-vol-10-by-ende-dot-app.mp3 (110 BPM)
- Music treatment: fade in under hook, low under scenes 2-3, swell into the
  verdict card (scene 4), dip for scene 5, fade out under outro
- Music cue guidance: preset JSON at brag skill
  assets/music/cues/happy-beats-business-moves-vol-10-by-ende-dot-app.music-cues.json;
  copy to composition assets. Lock the scene-4 verdict landing to a strong
  cue near 13s if present; scene-3 bars may tick consecutive beats (~0.55s
  spacing) while the serif caption holds.
- Audio-reactive treatment: subtle; verdict card warmth / signal-bar fill
  glow may breathe with RMS. No waveform or equalizer visuals.
- Audio-coupled moments:
  - Scene 1 typed subject — key ticks
  - Scene 2 chips — soft pops on beats
  - Scene 3 bars — tick per bar snap
  - Scene 4 verdict card — one announcement cue
  - Scene 6 outro — single soft close tick
- SFX selection guidance: sparse, motion-matched, low high-frequency risk
  for repeated ticks
- SFX analysis guidance: use the brag skill's assets/sfx/sfx-analysis.md
- Exact SFX choice: Hyperframes decides filenames, timestamps, density,
  volume.
- Audio files: copy the music into `brag-output/composition/assets/music/`;
  SFX chosen by Hyperframes land in the same assets tree.

## Hyperframes Instructions
Load the composition-building Hyperframes domain skills (hyperframes-core,
hyperframes-animation, hyperframes-creative, hyperframes-keyframes,
hyperframes-cli). This is a /brag run: do not enter the entry-point intent
interview and do not route into the generic promo workflow.

Requirements:
- Show at least one real UI/visual element from the project (the signal
  rows and verdict card from docs/how-it-works.html are the contract).
- Keep all text readable in the final render; hold the hook line and the
  reasons list to their reading floor.
- Keep the video at 20 seconds (15-25 allowed).
- Include the planned music/SFX layer.
- Recreate the layout style faithfully: warm monochrome, hairline cards,
  mono data, serif display lines. No gradients, no neon, no emojis.
- Run `hyperframes check` before render — the single gate.
