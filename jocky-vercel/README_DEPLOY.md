# JOCKY Dashboard — Vercel Deployment Guide

## What this deploys

A fully functional forensic intelligence dashboard that:
- Shows live agent status, evidence stream, blockchain COC
- Runs in DEMO MODE automatically (simulated data every 4 seconds)
- Switches to LIVE MODE if a local C2 server is detected at localhost:8000
- Works entirely from a single HTML file — no backend needed on Vercel

## Deploy to Vercel (3 steps)

### Step 1 — Create deployment folder

```
jocky-vercel/
    index.html      ← the dashboard
    vercel.json     ← deployment config
    package.json    ← metadata
    README.md       ← this file
```

Copy all four files into a new folder called `jocky-vercel`.

### Step 2 — Deploy via Vercel CLI

```bash
# install vercel cli (one time)
npm install -g vercel

# from inside jocky-vercel/
cd jocky-vercel
vercel

# follow prompts:
#   Set up and deploy? Y
#   Which scope? (your account)
#   Link to existing project? N
#   Project name: jocky-forensic-framework
#   In which directory is your code? ./
#   Want to override settings? N
```

Your URL will be: `https://jocky-forensic-framework.vercel.app`

### Step 3 — Or deploy via GitHub (even simpler)

1. Create a new GitHub repo: `jocky-dashboard`
2. Push these 4 files to it
3. Go to vercel.com → New Project → Import from GitHub
4. Select the repo → Deploy
5. Done — auto-deploys on every push

---

## For the SIH Presentation

### Option A — Vercel URL (show on any device)

Open `https://jocky-forensic-framework.vercel.app` on your laptop/phone.
Dashboard runs in DEMO MODE — evidence streams in every 4 seconds,
blockchain grows, anomaly alert fires automatically.

### Option B — Live mode (most impressive)

While showing the Vercel URL in browser:

```powershell
# on your laptop in Admin PowerShell (same machine as browser)
cd D:\Dinku\projects\JOCKY
python server/c2_server.py --host 0.0.0.0 --port 8000
```

The dashboard will auto-detect the local C2 and switch to LIVE MODE.
Then plug the USB into the VM target — real evidence flows into the
same dashboard the judges are watching.

### Demo flow for judges (90 seconds)

1. Open Vercel URL — dashboard loads, DEMO MODE running
2. Start local C2 — dashboard switches to LIVE MODE automatically
3. Plug USB into VM — agent connects, evidence stream activates
4. Click "Verify Chain" — blockchain verification runs live
5. Navigate Blockchain COC tab — show every signed block
6. Navigate USB Deploy tab — explain the zero-interaction workflow

---

## CORS note for live mode

When running local C2 and Vercel dashboard together, the C2 server
already has CORS enabled (allow_origins=["*"]) so the Vercel-hosted
dashboard can fetch from localhost:8000 without issues.
