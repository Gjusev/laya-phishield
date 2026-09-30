# Brag Plan: laya-phishield

## What is this app?
An explainable phishing detector: a local decision model answers eight atomic
yes/no questions about an email, a logistic head combines them into a score,
and every verdict names the reasons that fired it. Runs on CPU, costs $0 per
thousand emails.

## The angle
Every phishing demo shows you a score. This one shows you its homework. The
video is a single email walking the gauntlet: pre-pass flags pop, eight
signal bars fill with real measured values, the verdict lands with the three
reasons that pushed it. Then the twist: the same pipeline waves through a
legitimate email at 0.053. The credibility prop is that every number on
screen is real output from the shipped model, not marketing copy.

## Hook (first 2-3 seconds)
A phishing email slides in hard, subject line filling one word at a time:
"URGENT: Your account has been limited". A red stamp flashes: 0.59. Then the
whole frame shatters and rebuilds into eight small questions. Text: "one big
question is the wrong question."

## Key moments (the middle)
- The deterministic pre-pass fires its chips one by one: "display name
  claims a brand it does not own".
- Eight signal bars fill left to right with the real values (asks 0.92,
  link 0.91, urgency 0.86), each snapping to the beat.
- The verdict card lands: 0.990 PHISHING with its reasons list
  (asks_credentials +2.56, urgency_pressure +1.86, external_link_risk +1.56).
- Cut: the legit email (release notes) flows through the same machine, all
  bars dark, verdict 0.053 LEGITIMATE in green.

## Outro / punchline
"AUC 0.9531. Recall +21.8 points over the wide question. $0 per 1,000
emails." Logo line: laya-phishield. Sub: "eight narrow questions, one
verdict, every reason named."

## User flow worth showing
- Paste/scan an email (CLI line: `laya-phishield scan inbox.mbox` typing out)
- The pipeline filling (centerpiece, above)
- The verdict with reasons (the payoff)

## Tone
- Preset: polished
- Creative direction: security product demo with quiet confidence, editorial
  typography, warm monochrome
- Interpretation: fewer scenes, longer holds, no neon, no gimmicks. The
  numbers are the spectacle; motion stays restrained and precise.

## Format: landscape — 1920x1080
## Duration: 20s

## Visual identity (from the project)
- Background: #FBFBFA (warm off-white)
- Text: #111111 ink, #787774 muted
- Accent: #9F2F2D deep red (phishing) on #FDEBEC pale red; #346538 green
  (legit) on #EDF3EC; hairlines #EAEAEA
- Display font: serif (Georgia / Playfair-class) for the hook and outro
- Body font: system sans (Helvetica Neue / Segoe UI); all data in monospace
- Strongest visual element: the eight signal rows with red-filled bars from
  docs/how-it-works.html (reference: docs/assets/how-it-works-phish.png)

## Share copy (draft)
I stopped asking "is this email phishing?" and started asking eight narrow
questions. Every number in this video is real model output.

## Audio direction
- Role: warm bed with sparse professional accents
- Music: happy-beats-business-moves-vol-10 (110 BPM, preset cue file exists)
- Music treatment: fade in under the hook, hold low under the sequence,
  swell into the verdict card, fade under the outro
- Music cue guidance: preset cues/ JSON available; target the verdict-card
  landing on a strong cue near ~13s; sequential signal bars may tick on
  beats (110 BPM, ~0.55s spacing, fine for bars, hold text longer)
- Audio-reactive treatment: subtle; let the verdict card warmth and the
  signal-bar glow breathe with RMS, no waveform visuals
- SFX posture: sparse; key ticks for the typing hook, one soft stamp for the
  0.59 rejection, card sound for the verdict, nothing else
- Audio-coupled moments: typed subject (key ticks), bars snapping (ticks),
  verdict landing (single announcement cue)
- Restraint rule: no whooshes on every cut; music never covers the outro

## Storyboard

### Scene 1 — the wrong question — 3.5s
Warm off-white frame. The phishing email card slides in; subject types out
"URGENT: Your account has been limited". Red mono stamp "0.59" slams under
it, then the card shards/fades. Serif line lands: "one big question is the
wrong question."
Sequential/interaction: yes — subject types character by character; stamp
slams fast-in then holds ~1.2s
Audio intent: tension then dismissal
Audio-coupled idea: type the subject with key ticks; stamp gets one soft hit
Music: low bed, fade in
Transition mood: soft crossfade → Scene 2

### Scene 2 — the pre-pass — 3s
The email re-forms smaller; deterministic chips pop one by one: "display
name claims a brand it does not own", then a quiet chip "no other flag
fires". Mono caption: "deterministic pre-pass: headers, links, homoglyphs".
Sequential/interaction: yes — chips arrive one by one on beats
Audio intent: methodical, quiet confidence
Audio-coupled idea: chip pops tick on beats
Music: bed holds
Transition mood: slide → Scene 3

### Scene 3 — eight narrow questions — 5.5s
The centerpiece: eight signal rows (mono labels) fill with red bars, real
values landing right to left by size: asks 0.92, link 0.91, urgency 0.86,
brand 0.86, then four dim ones at 0.22/0.00. Serif caption above: "eight
narrow questions, one forward pass."
Sequential/interaction: yes — bars fill one by one on the beat grid, values
fade in with each
Audio intent: building precision
Audio-coupled idea: bar snaps on consecutive beats; text caption holds
throughout
Music: bed builds slightly
Transition mood: clean wipe → Scene 4

### Scene 4 — the verdict — 4s
Verdict card lands: huge mono "0.990" + pale-red pill "PHISHING". Below,
the three reasons count in: asks_credentials +2.56, urgency_pressure +1.86,
external_link_risk +1.56. This is the payoff; hold it.
Sequential/interaction: yes — reasons slide in one by one (~0.5s apart),
then full hold
Audio intent: payoff, warmth
Audio-coupled idea: single announcement cue on the card landing (strong cue
lock)
Music: swell then settle
Transition mood: hard cut → Scene 5

### Scene 5 — the other side — 2.5s
Same machine, one cut: the legit email (Release notes 1.4.2), all bars dark,
green verdict "0.053 LEGITIMATE". Caption: "the same pipeline waves it
through."
Sequential/interaction: no — arrives as one settled frame, holds
Audio intent: release, quiet
Audio-coupled idea: none
Music: bed dips
Transition mood: soft crossfade → Scene 6

### Scene 6 — outro — 1.5s
Serif: "eight narrow questions, one verdict, every reason named." Mono
footer: AUC 0.9531 / $0 per 1,000 emails / github.com/Gjusev/laya-phishield
Sequential/interaction: no
Audio intent: close
Audio-coupled idea: final tick under the logo line
Music: fade out

**Music mood for this video:** upbeat-professional (110 BPM), restrained mix
**Audio summary:** quiet build from typed tension to a single beat-locked
verdict payoff, then a green exhale and a soft close.
