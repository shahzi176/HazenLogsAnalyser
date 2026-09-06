# Nano Log Analyzer

A small local web app for reading hazenai ALPR application logs — either
already-decompressed log text files or raw NanoLog binary files straight off the container (`nano_logs_*`).
Upload a file, get an automatic pipeline-health check plus error/warning
summary, and search for a specific plate number to see its full
detection-to-publish timeline.

**NanoLog binary files are decompressed automatically** on upload using the
bundled `bin/decompressor` (built from the ALPR container's NanoLog runtime).
The app looks at the uploaded file's content, not its name or extension — if
it doesn't look like plain-text log lines, it's run through the decompressor
first, and the decompressed text is what gets analyzed (the decompressed
copy isn't kept — same as raw text uploads, only the parsed summary is
saved). If a file is neither readable text nor a valid NanoLog file, you'll
get a clear error instead of a crash.

## Run it

```
cd alpr-log-analyzer
pip3 install --user -r requirements.txt
python3 app.py
```

Then open **http://localhost:5001** in your browser (on this machine, or from
another device on the same network using this machine's IP instead of
`localhost`).

To use a different port: `PORT=8080 python3 app.py`.

## Run it in Docker

```
cd alpr-log-analyzer
docker compose up -d --build
```

Then open **http://localhost:5001** the same way as above. `docker-compose.yml`
maps port 5001 and stores `data/` (parsed analyses + retained log text) in a
named volume (`alpr_data`), so it survives container restarts and rebuilds.

Without Compose:

```
docker build -t alpr-log-analyzer .
docker run -d --name alpr-log-analyzer -p 5001:5001 -v alpr_data:/app/data alpr-log-analyzer
```

To use a different host port, change the left side of `-p` (e.g. `-p 8080:5001`)
or, with Compose, edit the `ports:` line in `docker-compose.yml`.

Logs: `docker logs -f alpr-log-analyzer`. Stop it: `docker compose down` (the
`alpr_data` volume — and everything you've uploaded — is kept; add `-v` to
also wipe it).

The image bundles the `bin/decompressor` binary, so NanoLog files work the
same as running locally. If a rebuilt/updated decompressor is ever needed,
replace `bin/decompressor` in this folder and re-run `docker compose up -d --build`.

## What it does

**Upload** — drop in a log `.txt` file on the home page. Files of 100MB+
parse in a few seconds; the page redirects to the summary once it's done.
Previously uploaded files stay listed on the home page. The parsed summary
is stored as JSON under `data/`, and the plain-text log itself (decompressed,
if it came from a NanoLog binary file) is kept alongside it as
`data/<id>_log.txt` so Text search / head / tail can read it later — this
means `data/` will end up roughly as big as the logs you've uploaded. Each
row in the "Previously analyzed files" list has a **Delete** link to remove
that one analysis (and its retained log text), and a **Delete all analyzed
logs** button clears everything in `data/` in one go — handy for keeping
disk usage down.

**Summary page**
- *Pipeline health* — automated findings: frame-processing stalls, channels
  re-created without being deleted (the classic "duplicate stream" overload),
  broker publish failure rate, GStreamer connect/read-timeout error clusters,
  climbing inference latency (resource contention), algorithm-container
  keepalive failures, and a heads-up when a log tail is quiet because there
  are simply no channels configured (not a failure).
- *At a glance* — channel create/delete counts, peak concurrent tasks,
  publish attempts, distinct plates, distinct plates actually confirmed
  published to RocketMQ, average FPS, error counts.
- *Error / warning types* — every distinct error and warning message,
  deduplicated and counted, with the first time each occurred.

**Plate search** — type a plate number (e.g. `8091XKH`) to get its complete
timeline: every raw detection, classification, tracker match, validity
check, and publish attempt, each with its exact timestamp, plus a verdict at
the top — **Published**, **Publish attempted but broker send failed**,
**Discarded by the validity gate**, or **Detected only**. An exact match
also shows a "Similar plates" card — other plates in the file of the same
length differing by only 1-2 characters (likely the same vehicle misread by
OCR), each shown as a pill colored **green** if that plate was confirmed
published to RocketMQ or **red** if it wasn't, and clickable to jump
straight to its own track. If there's no exact match, the page instead
suggests similar/substring matches as a plain list.

**Text search** — search any text across the raw log lines (error strings,
channel IDs, anything), with a configurable number of lines of context
before and after each hit, plus one-click **head** (first N lines) and
**tail** (last N lines) of the file — handy for eyeballing exactly what was
happening around a specific moment without downloading the whole log. All
matches show up together in one scrollable box (each with its own "line N"
marker), and this page uses the full width of your screen with long lines
wrapping instead of scrolling sideways.

A sample log (`sample_log.txt`, a real excerpt) is included in this folder
if you want to try the tool out immediately.

## How publish outcome is determined

The log doesn't put a direct link between a `Result::` line and the
RocketMQ send status that follows it — this app infers it by matching the
nearest send-success/send-failure line on the *same worker thread ID*
within a few seconds. This is a heuristic, not a guarantee; a result marked
"send outcome not found nearby" just means no matching status line was
close enough in the log to correlate confidently.

## Limitations / possible next steps

- The Flask dev server is fine for one person on one machine; if you want
  several people hitting it at once, put a real WSGI server in front of it.
- Stall detection uses a fixed 60-second threshold; edit `STALL_THRESHOLD`
  near the top of `parse_log()` in `app.py` if you want it more/less
  sensitive.
