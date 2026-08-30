#!/usr/bin/env python3
"""
ALPR Log Analyzer
------------------
A small local web app for reading hazenai ALPR application log files —
decompressed .txt logs (e.g. 03552logs1, 32_channels_logs.txt) or raw
NanoLog binary files (nano_logs_*), which are decompressed automatically
on upload via the bundled bin/decompressor.

Run:
    pip3 install --user flask
    python3 app.py
Then open http://localhost:5001 in your browser.

Upload a log file, get a summary of errors/warnings and automated
"pipeline health" findings, and search for a specific plate number to
see its full detection-to-publish timeline.
"""

import html
import io
import json
import os
import re
import subprocess
import time
import uuid
from collections import defaultdict, Counter, deque
from datetime import date as _date

from flask import Flask, request, render_template_string, redirect, url_for, jsonify, abort

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DECOMPRESSOR_BIN = os.path.join(APP_DIR, "bin", "decompressor")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1GB

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<file>\S+):(?P<lineno>\d+)\s+"
    r"(?P<level>[A-Z]+)\[(?P<tid>\d+)\]:\s?(?P<msg>.*)$"
)

RE_DOCKER_TAG = re.compile(r"Docker Tag:\s*(\S+)")
RE_CREATE_REQ = re.compile(r"Received Request: Create a video stream computing task.*?\"channelId\":\s*\"([^\"]+)\"")
RE_DELETE_REQ = re.compile(r"Received Request: Delete a video stream computing task.*?\"channelId\":\s*\"([^\"]+)\"")
RE_REMOVED_OK = re.compile(r"Channel (\S+) removed successfully, remaining channels: (\d+)")
RE_NONEXIST = re.compile(r"Non-existing Channel ID received in the DELETE request: (\S+)")
RE_STREAM_CREATED = re.compile(
    r"Stream created\. Dimension: (\d+) x (\d+)(?:\. Stream ID: (\S+), Internal ID: (\d+))?"
)
RE_ACTIVE_TASKS = re.compile(r"Number of Active Tasks: (\d+)")
RE_FPS = re.compile(r"Stream (\S+) running at ([\d.]+) fps")
RE_INFER_TIME = re.compile(r"Only Inference time:\s*(\d+)")
RE_COPY_TIME = re.compile(r"Total time to copy data:\s*(\d+)")
RE_PROCESSED_FRAME = re.compile(r"Processed a frame of stream id:\s*(\d+)")
RE_RETRY_COUNT = re.compile(r"retry count (\d+)")
RE_TIMEOUT_READ = re.compile(r"Timeout elapsed while trying to read frame.*Channel ID:\s*(\d+),\s*stream address (\S+)")
RE_EXC_READING = re.compile(r"Exception received while reading stream (\S+)")
RE_MAX_RETRY_NOT_OPENED = re.compile(r"MAX_RETRY_STREAM_NOT_OPENED.*defaulting to (\d+) retries")
RE_MAX_RETRY_STOPPED = re.compile(r"MAX_RETRY_STREAM_STOPPED.*defaulting to (\d+) retries")
RE_KEEPALIVE_FAIL = re.compile(r"POST request to http://[^/]+/algorithm/keepalive failed")

RE_RESULT = re.compile(
    r'Result:: cameraId "([^"]*)", PlateNo: "([^"]*)", PlateClass "([^"]*)", '
    r'Make: "([^"]*)", Model: "([^"]*)", Color: "([^"]*)", PlateRegion: "([^"]*)", '
    r"PlateRegionScore: ([\d.]+), first timestamp: (\d+)"
)
RE_SEND_FAIL = re.compile(r"send message\[([^\]]*)\] failed ! Status code: (-?\d+)")
RE_SEND_OK = re.compile(r"send message\[([^\]]*)\] result status:\s*(\d+),\s*msgId:\s*(\S+)")
RE_TOPIC_NOTFOUND = re.compile(r"Could not find the publishing topic from the channel ID:\s*(\S*)")

RE_RAW_PLATE = re.compile(
    r"ALPR PLATE:\s*(\S+)\s*\|\s*Score\s*([\d.]+)\s*\|\s*Obj Score\s*([\d.]+)\s*\|\s*Template\s*(\S+)\s*\|\s*ALPR BOX:\s*([\d.\- ]+)"
)
RE_OCR = re.compile(
    r"OCR is:\s*(\S+)\s*Plate Color:\s*(\S+)\s*Plate Color Conf:\s*([\d.]+)\s*"
    r"Plate Category:\s*(\S+)\s*Plate Category Conf:\s*([\d.]+)(?:\s*Plate Country:\s*(\S*))?(?:\s*Plate State:\s*(\S*))?"
)
RE_NEW_TRACK = re.compile(r"no match found, new OCR:\s*(\S+)")
RE_MATCH = re.compile(r"OCR:\s*(\S+) match found with OCR:\s*(\S+), match kept, (larger|smaller) area")
RE_SAME_AREA = re.compile(r"Same OCR:\s*(\S+), (larger|smaller) area")
RE_SAME_CONF = re.compile(r"Same OCR:\s*(\S+), (low|high) confidence")
RE_CHANGED = re.compile(r"OCR Changed from\s*(\S+) to\s*(\S+), (larger|smaller) area")
RE_TRACK_END = re.compile(r"track ended for OCR:\s*(\S+) last ts:\s*(\d+), start ts:\s*(\d+)")
RE_TRACK_PUSHED = re.compile(
    r"track pushed for OCR:\s*(\S+) last ts:\s*(\d+), start ts:\s*(\d+), category:\s*(\S+), category confidence:\s*([\d.]+)"
)
RE_RECEIVED_TRACK = re.compile(
    r"received track with OCR:\s*(\S+), ocr socre:\s*([\d.]+), track_validity:\s*(\d+), publish_threshold:\s*([\d.]+)"
)
RE_CHANNELID_MAP = re.compile(r"ChannelId:\s*(\S+), hazenId:\s*(\d+)\s*,OCR:\s*(\S+)")
RE_DETECTIONS_COUNT = re.compile(r"for OCR:\s*(\S+) number of detections are (\d+)")


def norm_msg(msg):
    """Normalize a log message for grouping: collapse numbers/ids so
    'send message[X] failed! Status code: 123' and '...Status code: -456'
    count as the same error type."""
    m = re.sub(r"-?\d+(\.\d+)?", "N", msg)
    m = re.sub(r'"[^"]*"', '"…"', m)
    return m.strip()


def plate_event(store, plate, ts, stage, detail, raw, tid):
    store[plate].append({"ts": ts, "stage": stage, "detail": detail, "raw": raw, "tid": tid})


# One distinct color per pipeline stage, used for both the timeline dots/
# badges and the summary sidebar on the plate-tracking page.
STAGE_COLORS = {
    "detected": "#6fb3f2",
    "classified": "#58c4b8",
    "classified (after threshold)": "#3fae9e",
    "track started": "#b58bf0",
    "track matched": "#8b93f0",
    "track relabeled": "#e0b34d",
    "track ended": "#93a1b4",
    "validity check (passed)": "#5fbf7a",
    "validity check (failed — discarded)": "#c46b62",
    "track pushed to publisher": "#f0a15c",
    "channel assigned": "#d98bd0",
    "published": "#ff9a44",
}
DEFAULT_STAGE_COLOR = "#93a1b4"


def stage_color(stage, detail=""):
    if stage == "publish result":
        if "confirmed" in detail:
            return "#5fbf7a"
        if "FAILED" in detail:
            return "#c46b62"
        return "#93a1b4"
    return STAGE_COLORS.get(stage, DEFAULT_STAGE_COLOR)


def plate_is_published(evs):
    """True if this plate's event list contains a confirmed broker publish."""
    return any(e["stage"] == "publish result" and "confirmed" in e["detail"] for e in evs)


def hamming_dist(a, b):
    return sum(1 for x, y in zip(a, b) if x != y)


def find_close_plates(q, all_plates, max_dist=2, limit=20):
    """Plates of the same length as q, differing in only 1-2 characters
    (e.g. searching 3642ERA also finds 3642EBA) — used on the plate-search
    page both to suggest near-misses and to surface likely-same-vehicle
    variants next to an exact match."""
    if not q or len(q) < 4:
        return []
    out = []
    for p in all_plates:
        if p == q or len(p) != len(q):
            continue
        d = hamming_dist(q, p)
        if 1 <= d <= max_dist:
            out.append((d, p))
    out.sort(key=lambda x: (x[0], x[1]))
    return [p for _, p in out[:limit]]


def _looks_like_log_text(sample):
    """Heuristic: does this byte sample look like an already-decompressed
    ALPR log (UTF-8 text with recognizable TIMESTAMP FILE:LINE LEVEL[TID]:
    msg lines), as opposed to a raw NanoLog binary file?"""
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [ln for ln in text.splitlines() if ln.strip()][:20]
    if not lines:
        return False
    hits = sum(1 for ln in lines if LINE_RE.match(ln))
    return hits >= max(1, len(lines) // 2)


def decompress_nano_log(raw_path):
    """Try to decompress a raw upload as a NanoLog binary log file (the
    format the ALPR container writes as nano_logs_*) into plain text using
    the bundled `decompressor` binary. Returns (decoded_path, error) —
    decoded_path is None and error is a user-facing message on failure."""
    if not os.path.isfile(DECOMPRESSOR_BIN):
        return None, "NanoLog decompressor binary is not installed on this server (expected at bin/decompressor)."
    if not os.access(DECOMPRESSOR_BIN, os.X_OK):
        try:
            os.chmod(DECOMPRESSOR_BIN, 0o755)
        except OSError:
            pass
    decoded_path = raw_path + ".decoded.txt"
    try:
        with open(decoded_path, "wb") as out:
            proc = subprocess.run(
                [DECOMPRESSOR_BIN, "decompress", raw_path],
                stdout=out, stderr=subprocess.PIPE, timeout=300,
            )
    except subprocess.TimeoutExpired:
        _silent_remove(decoded_path)
        return None, "Decompression timed out — the file may be too large or not a NanoLog binary file."
    except OSError as e:
        _silent_remove(decoded_path)
        return None, f"Could not run the NanoLog decompressor: {e}"

    ok_size = os.path.isfile(decoded_path) and os.path.getsize(decoded_path) > 0
    if proc.returncode != 0 or not ok_size:
        _silent_remove(decoded_path)
        err = proc.stderr.decode("utf-8", "replace").strip()
        err = (": " + err[:400]) if err else "."
        return None, f"Could not decompress this file as a NanoLog binary log{err}"

    with open(decoded_path, "rb") as fchk:
        head = fchk.read(8192)
    if not _looks_like_log_text(head):
        _silent_remove(decoded_path)
        return None, "Decompression ran but the output didn't look like an ALPR log — this may not be a NanoLog file."
    return decoded_path, None


def _silent_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def parse_log(path):
    level_counts = Counter()
    warn_types = Counter()
    error_types = Counter()
    warn_sample = {}
    error_sample = {}

    creates = []
    deletes = []
    removed_ok = []
    nonexist = []
    stream_created = []
    active_tasks = []

    fps_samples = []
    infer_times = []
    copy_times = []
    processed_frame_ts = []

    gst_connect_fail_ts = []
    gst_read_timeout_ts = []
    gst_exception_ts = []
    retry_counts = Counter()
    max_retry_not_opened = None
    max_retry_stopped = None
    keepalive_fail_count = 0

    results = []          # list of dict: ts, tid, cameraId, plateNo, ...
    send_fail = []        # list of dict: ts, tid, topic, status
    send_ok = []          # list of dict: ts, tid, topic, status, msgId
    topic_notfound = []

    plate_events = defaultdict(list)

    docker_tag = None
    first_ts = None
    last_ts = None
    total_lines = 0
    unparsed_lines = 0

    with io.open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw_line in f:
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            total_lines += 1
            m = LINE_RE.match(line)
            if not m:
                unparsed_lines += 1
                continue
            ts, level, tid, msg = m.group("ts"), m.group("level"), int(m.group("tid")), m.group("msg")
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            level_counts[level] += 1

            if level in ("WARNING", "ERROR"):
                key = norm_msg(msg)
                bucket = warn_types if level == "WARNING" else error_types
                sample = warn_sample if level == "WARNING" else error_sample
                bucket[key] += 1
                if key not in sample:
                    sample[key] = {"ts": ts, "raw": msg}

            if docker_tag is None:
                dm = RE_DOCKER_TAG.search(msg)
                if dm:
                    docker_tag = dm.group(1)

            # --- channel / task lifecycle ---
            if "Create a video stream computing task" in msg:
                cm = RE_CREATE_REQ.search(msg)
                if cm:
                    creates.append({"ts": ts, "channelId": cm.group(1)})
            elif "Delete a video stream computing task" in msg:
                dmr = RE_DELETE_REQ.search(msg)
                if dmr:
                    deletes.append({"ts": ts, "channelId": dmr.group(1)})
            elif "removed successfully" in msg:
                rm = RE_REMOVED_OK.search(msg)
                if rm:
                    removed_ok.append({"ts": ts, "channelId": rm.group(1), "remaining": int(rm.group(2))})
            elif "Non-existing Channel ID" in msg:
                nm = RE_NONEXIST.search(msg)
                if nm:
                    nonexist.append({"ts": ts, "channelId": nm.group(1)})
            elif "Stream created. Dimension" in msg:
                sm = RE_STREAM_CREATED.search(msg)
                if sm:
                    stream_created.append({
                        "ts": ts, "w": sm.group(1), "h": sm.group(2),
                        "streamId": sm.group(3), "internalId": sm.group(4), "tid": tid,
                    })
            elif "Number of Active Tasks" in msg:
                am = RE_ACTIVE_TASKS.search(msg)
                if am:
                    active_tasks.append({"ts": ts, "count": int(am.group(1))})

            # --- fps / timing ---
            if "running at" in msg and "fps" in msg:
                fm = RE_FPS.search(msg)
                if fm:
                    fps_samples.append({"ts": ts, "url": fm.group(1), "fps": float(fm.group(2))})
            if "Only Inference time" in msg:
                im = RE_INFER_TIME.search(msg)
                if im:
                    infer_times.append({"ts": ts, "ms": int(im.group(1))})
            if "Total time to copy data" in msg:
                cm2 = RE_COPY_TIME.search(msg)
                if cm2:
                    copy_times.append({"ts": ts, "ms": int(cm2.group(1))})
            if "Processed a frame of stream id" in msg:
                processed_frame_ts.append(ts)

            # --- gstreamer / stream errors ---
            if "Failed to play the stream" in msg or msg.strip() == "Unknown GST error":
                gst_connect_fail_ts.append(ts)
            if "Timeout elapsed while trying to read frame" in msg:
                gst_read_timeout_ts.append(ts)
            if "Exception received while reading stream" in msg:
                gst_exception_ts.append(ts)
            rcm = RE_RETRY_COUNT.search(msg)
            if rcm:
                retry_counts[int(rcm.group(1))] += 1
            if max_retry_not_opened is None:
                mn = RE_MAX_RETRY_NOT_OPENED.search(msg)
                if mn:
                    max_retry_not_opened = int(mn.group(1))
            if max_retry_stopped is None:
                ms_ = RE_MAX_RETRY_STOPPED.search(msg)
                if ms_:
                    max_retry_stopped = int(ms_.group(1))
            if RE_KEEPALIVE_FAIL.search(msg):
                keepalive_fail_count += 1

            # --- publish path ---
            if msg.startswith("Result:: cameraId") or "Result:: cameraId" in msg:
                res = RE_RESULT.search(msg)
                if res:
                    rec = {
                        "ts": ts, "tid": tid,
                        "cameraId": res.group(1), "plateNo": res.group(2), "plateClass": res.group(3),
                        "make": res.group(4), "model": res.group(5), "color": res.group(6),
                        "region": res.group(7), "regionScore": res.group(8), "firstTs": res.group(9),
                    }
                    results.append(rec)
                    plate_event(plate_events, res.group(2), ts, "published", "Result assembled for publish", msg, tid)
            if "send message" in msg and "failed" in msg:
                sf = RE_SEND_FAIL.search(msg)
                if sf:
                    send_fail.append({"ts": ts, "tid": tid, "topic": sf.group(1), "status": sf.group(2)})
            elif "send message" in msg and "result status" in msg:
                so = RE_SEND_OK.search(msg)
                if so:
                    send_ok.append({"ts": ts, "tid": tid, "topic": so.group(1), "status": so.group(2), "msgId": so.group(3)})
            if "Could not find the publishing topic" in msg:
                tn = RE_TOPIC_NOTFOUND.search(msg)
                if tn:
                    topic_notfound.append({"ts": ts, "channelId": tn.group(1)})

            # --- plate lifecycle events ---
            if "ALPR PLATE:" in msg:
                pm = RE_RAW_PLATE.search(msg)
                if pm:
                    plate_event(plate_events, pm.group(1), ts, "detected",
                                f"score {pm.group(2)}, obj score {pm.group(3)}, template {pm.group(4)}", msg, tid)
            if "OCR is:" in msg:
                om = RE_OCR.search(msg)
                if om:
                    stage = "classified (after threshold)" if "After Thresholding" in msg else "classified"
                    plate_event(plate_events, om.group(1), ts, stage,
                                f"color {om.group(2)} ({om.group(3)}), category {om.group(4)} ({om.group(5)})", msg, tid)
            if "no match found, new OCR" in msg:
                nt = RE_NEW_TRACK.search(msg)
                if nt:
                    plate_event(plate_events, nt.group(1), ts, "track started", "new track opened", msg, tid)
            if "match found with OCR" in msg:
                mm = RE_MATCH.search(msg)
                if mm:
                    plate_event(plate_events, mm.group(1), ts, "track matched", f"matched existing OCR {mm.group(2)} ({mm.group(3)} area)", msg, tid)
                    if mm.group(2) != mm.group(1):
                        plate_event(plate_events, mm.group(2), ts, "track matched", f"matched incoming OCR {mm.group(1)} ({mm.group(3)} area)", msg, tid)
            if "OCR Changed from" in msg:
                chm = RE_CHANGED.search(msg)
                if chm:
                    plate_event(plate_events, chm.group(1), ts, "track relabeled", f"changed to {chm.group(2)}", msg, tid)
                    plate_event(plate_events, chm.group(2), ts, "track relabeled", f"changed from {chm.group(1)}", msg, tid)
            if "track ended for OCR" in msg:
                te = RE_TRACK_END.search(msg)
                if te:
                    plate_event(plate_events, te.group(1), ts, "track ended",
                                f"start ts {te.group(3)}, last ts {te.group(2)}", msg, tid)
            if "track pushed for OCR" in msg:
                tp = RE_TRACK_PUSHED.search(msg)
                if tp:
                    plate_event(plate_events, tp.group(1), ts, "track pushed to publisher",
                                f"category {tp.group(4)} ({tp.group(5)})", msg, tid)
            if "received track with OCR" in msg:
                rt = RE_RECEIVED_TRACK.search(msg)
                if rt:
                    valid = rt.group(3) == "1"
                    plate_event(plate_events, rt.group(1), ts,
                                "validity check (passed)" if valid else "validity check (failed — discarded)",
                                f"score {rt.group(2)}, threshold {rt.group(4)}", msg, tid)
            if "ChannelId:" in msg and ",OCR:" in msg:
                cim = RE_CHANNELID_MAP.search(msg)
                if cim:
                    plate_event(plate_events, cim.group(3), ts, "channel assigned",
                                f"channel {cim.group(1)}, hazenId {cim.group(2)}", msg, tid)

    # --- resolve publish status per Result:: record ---
    fail_by_tid = defaultdict(list)
    for sf in send_fail:
        fail_by_tid[sf["tid"]].append(sf)
    ok_by_tid = defaultdict(list)
    for so in send_ok:
        ok_by_tid[so["tid"]].append(so)

    _epoch_date_cache = {}

    def ts_to_epoch(ts):
        # ts like '2026-08-27 10:28:37.436122149' -> true sortable seconds,
        # including the date, so it works across midnight/day boundaries and
        # multi-day log files without any wraparound guessing.
        try:
            date_part, time_part = ts.split(" ")
            day_base = _epoch_date_cache.get(date_part)
            if day_base is None:
                y, mo, da = (int(x) for x in date_part.split("-"))
                day_base = (_date(y, mo, da) - _date(1970, 1, 1)).days * 86400
                _epoch_date_cache[date_part] = day_base
            h, mi, s = time_part.split(":")
            return day_base + int(h) * 3600 + int(mi) * 60 + float(s)
        except Exception:
            return 0.0

    for rec in results:
        t0 = ts_to_epoch(rec["ts"])
        tid = rec["tid"]
        best = None
        best_dt = 999999
        outcome = "unknown"
        for sf in fail_by_tid.get(tid, []):
            dt = abs(ts_to_epoch(sf["ts"]) - t0)
            if dt < best_dt and dt <= 3.0:
                best_dt = dt
                best = sf
                outcome = "failed"
        for so in ok_by_tid.get(tid, []):
            dt = abs(ts_to_epoch(so["ts"]) - t0)
            if dt < best_dt and dt <= 3.0:
                best_dt = dt
                best = so
                outcome = "published"
        rec["publishOutcome"] = outcome
        rec["publishDetail"] = best
        plate_events[rec["plateNo"]].append({
            "ts": rec["ts"], "stage": "publish result",
            "detail": ("send to broker FAILED — " + str(best.get("status")) if outcome == "failed"
                       else "send to broker confirmed" if outcome == "published"
                       else "no matching send-status line found nearby (unknown outcome)"),
            "raw": "", "tid": tid,
        })

    for plate, evs in plate_events.items():
        evs.sort(key=lambda e: e["ts"])

    # --- findings engine ---
    findings = []

    def add_finding(severity, title, detail):
        findings.append({"severity": severity, "title": title, "detail": detail})

    # 1. frame-processing stalls
    stalls = []
    STALL_THRESHOLD = 60.0
    if len(processed_frame_ts) >= 2:
        prev_ts = processed_frame_ts[0]
        prev_epoch = ts_to_epoch(prev_ts)
        for t in processed_frame_ts[1:]:
            cur_epoch = ts_to_epoch(t)
            gap = cur_epoch - prev_epoch
            # Interleaved worker threads can log a few ms out of order; that's
            # not a stall. Only a large negative gap would mean a genuinely
            # unsorted/corrupt file, which we don't try to "correct" for.
            if gap > STALL_THRESHOLD:
                stalls.append({"start_ts": prev_ts, "end_ts": t, "duration": gap})
            if gap > 0:
                prev_ts, prev_epoch = t, cur_epoch
    for st in stalls:
        mins = st["duration"] / 60.0
        add_finding(
            "critical" if mins > 5 else "warning",
            f"Frame processing stalled for {mins:.1f} minutes",
            f"No 'Processed a frame' events between {st['start_ts']} and {st['end_ts']}. "
            f"Check the active-channel count and inference timing around this window."
        )

    # 2. duplicate channel creates without interleaved deletes
    by_channel_creates = defaultdict(list)
    for c in creates:
        by_channel_creates[c["channelId"]].append(c["ts"])
    by_channel_deletes = defaultdict(int)
    for d in deletes:
        by_channel_deletes[d["channelId"]] += 1
    dup_channels = []
    for chan, ts_list in by_channel_creates.items():
        ndel = by_channel_deletes.get(chan, 0)
        if len(ts_list) > 1 and len(ts_list) > ndel + 1:
            dup_channels.append((chan, len(ts_list), ndel))
    if dup_channels:
        detail = "; ".join(f"{c} created {n}x with only {d} deletes" for c, n, d in dup_channels)
        add_finding("critical", f"{len(dup_channels)} channel ID(s) re-created without matching deletes",
                    "Repeated create requests for the same channel ID without an intervening delete stack up "
                    "duplicate concurrent stream workers, overloading shared inference. " + detail)

    # 3. publish failures
    total_publish_attempts = len(results)
    total_send_fail = len(send_fail)
    total_send_ok = len(send_ok)
    if total_publish_attempts > 0:
        fail_rate = total_send_fail / max(1, total_publish_attempts)
        if total_send_ok == 0 and total_send_fail > 0:
            add_finding("critical", "Every publish attempt failed to reach the broker",
                        f"{total_send_fail} 'send message failed' errors logged against {total_publish_attempts} "
                        f"Result:: records, and zero successful sends found. Check the RocketMQ connection/producer.")
        elif fail_rate > 0.2:
            add_finding("warning", f"{fail_rate*100:.0f}% of publish attempts failed",
                        f"{total_send_fail} failed sends vs {total_send_ok} confirmed successes.")

    # 4. keepalive
    if keepalive_fail_count > 0:
        add_finding("warning", f"Algorithm-container keepalive failed {keepalive_fail_count}x",
                    "Recurring 'Connection refused' on the local algorithm-container keepalive endpoint (port 3333).")

    # 5. gstreamer clusters + retry ceiling
    if gst_connect_fail_ts or gst_read_timeout_ts:
        max_seen_retry = max(retry_counts.keys()) if retry_counts else 0
        ceiling = max(filter(None, [max_retry_not_opened, max_retry_stopped])) if (max_retry_not_opened or max_retry_stopped) else None
        note = ""
        if ceiling and max_seen_retry >= ceiling:
            note = f" At least one incident reached the configured retry ceiling ({ceiling}) — check whether it actually recovered."
        add_finding("info" if not note else "warning",
                    f"{len(gst_connect_fail_ts)} stream connect failures, {len(gst_read_timeout_ts)} read-timeouts",
                    "GStreamer had to retry/reconnect during this run." + note)

    # 6. latency / fps trend
    if len(infer_times) > 20:
        n = len(infer_times)
        first_chunk = infer_times[: n // 5] if n >= 5 else infer_times
        last_chunk = infer_times[-(n // 5):] if n >= 5 else infer_times
        avg_first = sum(x["ms"] for x in first_chunk) / len(first_chunk)
        avg_last = sum(x["ms"] for x in last_chunk) / len(last_chunk)
        if avg_first > 0 and avg_last > avg_first * 2.5:
            add_finding("warning", "Inference latency climbed significantly over the run",
                        f"Average inference time went from ~{avg_first:.0f}ms early in the run to ~{avg_last:.0f}ms "
                        f"later — consistent with GPU/CPU contention from too many concurrent streams.")

    # 7. idle tail (zero channels for a long time with no more requests)
    if removed_ok and creates:
        last_remove = removed_ok[-1]
        if last_remove["remaining"] == 0:
            last_activity_ts = max(
                [c["ts"] for c in creates] + [d["ts"] for d in deletes] + [last_remove["ts"]]
            )
            if last_ts and ts_to_epoch(last_ts) - ts_to_epoch(last_activity_ts) > 300:
                idle_min = (ts_to_epoch(last_ts) - ts_to_epoch(last_activity_ts)) / 60.0
                add_finding("info", f"No channels configured for the final {idle_min:.0f} minutes of this log",
                            "All channels were removed and none were re-created — the app correctly produced "
                            "nothing after this point because there was nothing left to process.")

    # 8. category classifier spam (cosmetic)
    cat_spam = sum(v for k, v in error_types.items() if "is not valid. Sending generic color" in k)
    if cat_spam > 0:
        add_finding("info", f"'Given category … is not valid' logged {cat_spam}x",
                    "Cosmetic classifier warning (falls back to a default color) — not a pipeline failure.")

    severity_rank = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: severity_rank.get(f["severity"], 3))

    summary = {
        "file_first_ts": first_ts,
        "file_last_ts": last_ts,
        "total_lines": total_lines,
        "unparsed_lines": unparsed_lines,
        "docker_tag": docker_tag,
        "level_counts": dict(level_counts),
        "warn_types": [{"msg": k, "count": v, **warn_sample[k]} for k, v in warn_types.most_common(25)],
        "error_types": [{"msg": k, "count": v, **error_sample[k]} for k, v in error_types.most_common(25)],
        "channels": {
            "create_requests": len(creates),
            "delete_requests": len(deletes),
            "removed_ok": len(removed_ok),
            "rejected_deletes": len(nonexist),
            "distinct_channel_ids_created": len(by_channel_creates),
            "peak_active_tasks": max((a["count"] for a in active_tasks), default=None),
            "stream_creates_total": len(stream_created),
            "active_tasks_series": active_tasks,
        },
        "fps": {
            "count": len(fps_samples),
            "avg": (sum(x["fps"] for x in fps_samples) / len(fps_samples)) if fps_samples else None,
            "min": min((x["fps"] for x in fps_samples), default=None),
            "max": max((x["fps"] for x in fps_samples), default=None),
        },
        "gst": {
            "connect_failures": len(gst_connect_fail_ts),
            "read_timeouts": len(gst_read_timeout_ts),
            "exceptions": len(gst_exception_ts),
            "max_retry_not_opened": max_retry_not_opened,
            "max_retry_stopped": max_retry_stopped,
        },
        "publish": {
            "results": total_publish_attempts,
            "distinct_plates": len(set(r["plateNo"] for r in results)),
            "distinct_plates_published": len(set(r["plateNo"] for r in results if r["publishOutcome"] == "published")),
            "send_fail": total_send_fail,
            "send_ok": total_send_ok,
            "topic_notfound": len(topic_notfound),
        },
        "keepalive_fail_count": keepalive_fail_count,
        "stalls": stalls,
        "findings": findings,
    }

    return {
        "summary": summary,
        "results": results,
        "plates": {p: evs for p, evs in plate_events.items()},
    }


def raw_log_path_for(file_id):
    return os.path.join(DATA_DIR, f"{file_id}_log.txt")


def esc(text):
    return html.escape(text, quote=False)


def _iter_log_lines(path):
    with io.open(path, "r", encoding="utf-8", errors="replace") as f:
        for i, raw in enumerate(f, start=1):
            yield i, raw.rstrip("\n")


def head_lines(path, n):
    out = []
    for i, line in _iter_log_lines(path):
        out.append((i, line))
        if len(out) >= n:
            break
    return out


def tail_lines(path, n):
    buf = deque(maxlen=n)
    for rec in _iter_log_lines(path):
        buf.append(rec)
    return list(buf)


def search_text_lines(path, query, before=0, after=0, case_sensitive=False, max_hits=300):
    """Grep-like streaming search: each match becomes its own block with
    `before` lines of leading context and `after` lines of trailing context.
    Matches are not merged even if their context windows overlap — simpler
    and still gives every hit its own clearly-marked line."""
    if not query:
        return [], False
    q = query if case_sensitive else query.lower()
    before = max(0, min(before, 500))
    after = max(0, min(after, 500))
    max_hits = max(1, min(max_hits, 1000))

    ring = deque(maxlen=before) if before > 0 else None
    blocks = []
    pending = []  # list of [block, remaining_after]
    truncated = False

    for i, line in _iter_log_lines(path):
        if pending:
            still_pending = []
            for blk, rem in pending:
                blk["lines"].append((i, line, False))
                rem -= 1
                if rem > 0:
                    still_pending.append([blk, rem])
            pending = still_pending

        hay = line if case_sensitive else line.lower()
        if q in hay:
            if len(blocks) < max_hits:
                lines = [(ln, txt, False) for ln, txt in ring] if ring else []
                lines.append((i, line, True))
                blk = {"match_line": i, "lines": lines}
                blocks.append(blk)
                if after > 0:
                    pending.append([blk, after])
            else:
                truncated = True
                if not pending:
                    break

        if ring is not None:
            ring.append((i, line))

    return blocks, truncated


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def save_analysis(file_id, name, analysis):
    path = os.path.join(DATA_DIR, f"{file_id}.json")
    with io.open(path, "w", encoding="utf-8") as f:
        json.dump({"name": name, **analysis}, f)


def load_analysis(file_id):
    path = os.path.join(DATA_DIR, f"{file_id}.json")
    if not os.path.exists(path):
        abort(404)
    with io.open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def list_analyses():
    out = []
    for fn in sorted(os.listdir(DATA_DIR), reverse=True):
        if fn.endswith(".json"):
            fid = fn[:-5]
            try:
                with io.open(os.path.join(DATA_DIR, fn), "r", encoding="utf-8") as f:
                    d = json.load(f)
                out.append({
                    "id": fid, "name": d.get("name"),
                    "first_ts": d["summary"]["file_first_ts"], "last_ts": d["summary"]["file_last_ts"],
                    "lines": d["summary"]["total_lines"],
                })
            except Exception:
                continue
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

BASE_HTML = """
<!doctype html>
<html data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} · ALPR Log Analyzer</title>
<style>
  :root {
    --bg:#10141b; --surface:#171d27; --surface2:#1e2632; --border:#2c3542;
    --text:#e9edf3; --dim:#93a1b4; --faint:#5f6b7d;
    --accent:#ff9a44; --good:#5fbf7a; --bad:#c46b62; --warn:#e0b34d;
    --mono: "IBM Plex Mono", ui-monospace, Menlo, monospace;
    --sans: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); line-height:1.55; }
  a { color: var(--accent); }
  .wrap { max-width: 1040px; margin: 0 auto; padding: 32px 24px 80px; }
  .wrap.wide { max-width: min(1700px, 96vw); }
  header.top { display:flex; align-items:baseline; justify-content:space-between; margin-bottom: 28px; flex-wrap:wrap; gap:8px;}
  header.top h1 { font-size: 20px; margin:0; }
  header.top nav a { margin-left: 16px; font-size: 14px; color: var(--dim); text-decoration:none; }
  header.top nav a:hover { color: var(--text); }
  h2 { font-size: 18px; margin: 36px 0 12px; }
  h3 { font-size: 14px; margin: 20px 0 8px; color: var(--dim); text-transform:uppercase; letter-spacing:.05em; }
  .card { background: var(--surface); border:1px solid var(--border); border-radius:10px; padding:18px 20px; }
  .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(160px,1fr)); gap:10px; }
  .stat { background: var(--surface); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
  .stat .v { font-family:var(--mono); font-size:20px; font-weight:600; font-variant-numeric:tabular-nums; }
  .stat .l { font-size:12px; color:var(--faint); margin-top:2px; }
  table { border-collapse: collapse; width:100%; font-size: 13px; }
  th, td { text-align:left; padding: 7px 10px; border-bottom:1px solid var(--border); vertical-align:top;}
  th { color: var(--faint); font-weight:500; text-transform:uppercase; font-size:11px; letter-spacing:.04em; }
  code, .mono { font-family: var(--mono); font-size: 12.5px; }
  .badge { display:inline-block; padding:2px 8px; border-radius:99px; font-size:11px; font-family:var(--mono); }
  .sev-critical { background:#3a2523; color: var(--bad); border:1px solid var(--bad); }
  .sev-warning { background:#3a3320; color: var(--warn); border:1px solid var(--warn); }
  .sev-info { background:#1c2530; color: var(--dim); border:1px solid var(--border); }
  .out-published { color: var(--good); }
  .out-failed { color: var(--bad); }
  .out-unknown { color: var(--faint); }
  .finding { padding:12px 14px; border-radius:8px; margin-bottom:10px; border:1px solid var(--border); background:var(--surface2); }
  .finding .title { font-weight:600; margin-bottom:4px; }
  .finding .detail { font-size:13px; color:var(--dim); }
  form.upload { border:1px dashed var(--border); border-radius:10px; padding:28px; text-align:center; }
  input[type=text], input[type=file] { font-family:var(--sans); }
  input[type=text] { background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:9px 12px; border-radius:6px; width: 260px; }
  button, .btn { background:var(--accent); border:none; color:#1a1206; font-weight:600; padding:9px 16px; border-radius:6px; cursor:pointer; font-size:14px; text-decoration:none; display:inline-block;}
  button.secondary, .btn.secondary { background:var(--surface2); color:var(--text); border:1px solid var(--border); }
  .muted { color: var(--faint); font-size: 13px; }
  .filelist a { text-decoration:none; color: var(--text); }
  .filelist li { list-style:none; padding:10px 0; border-bottom:1px solid var(--border);
    display:flex; align-items:baseline; justify-content:space-between; gap:12px; flex-wrap:wrap; }
  .filelist .fl-info { flex:1 1 auto; min-width:0; }
  .inline-form { display:inline; flex:none; }
  .link-danger { background:none; border:none; color:var(--bad); font-size:12.5px; cursor:pointer;
    padding:2px 4px; text-decoration:underline; font-family:var(--sans); }
  .link-danger:hover { color:#e08b82; }
  .btn-danger { background:#3a2523; color: var(--bad); border:1px solid var(--bad); }
  .btn-danger:hover { background:#452a28; }
  .timeline { border-left:2px solid var(--border); margin-left:6px; padding-left:16px; }
  .tl-item { position:relative; padding-bottom:16px; }
  .tl-item::before { content:""; position:absolute; left:-21px; top:5px; width:9px; height:9px; border-radius:50%; background: var(--dot-color, var(--accent)); box-shadow: 0 0 0 3px var(--bg); }
  .tl-ts { font-family:var(--mono); font-size:12px; color:var(--faint); }
  .tl-stage { display:inline-block; font-weight:600; font-size:11.5px; letter-spacing:.02em; margin: 3px 0 4px; padding: 2px 9px; border-radius: 99px; }
  .tl-detail { font-size:13px; color:var(--dim); }
  .plate-layout { display:grid; grid-template-columns: 1fr 280px; gap: 28px; align-items:start; }
  @media (max-width: 720px) { .plate-layout { grid-template-columns: 1fr; } }
  .side-summary { position:sticky; top:20px; }
  .side-summary .verdict-card { margin-bottom:14px; padding:14px 16px; }
  .count-row { display:flex; justify-content:space-between; align-items:center; padding:7px 0; border-bottom:1px solid var(--border); font-size:13px; }
  .count-row:last-child { border-bottom:none; }
  .count-row .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px; flex:none; }
  .count-row .label { display:flex; align-items:center; color:var(--dim); }
  .count-row .num { font-family:var(--mono); font-weight:600; font-variant-numeric:tabular-nums; }
  .headline-stats { display:grid; grid-template-columns: 1fr 1fr; gap:8px; margin-bottom:14px; }
  .headline-stats .stat .v { font-size:22px; }
  .plate-group-card { margin-bottom:10px; padding:12px 14px; }
  .plate-pill { display:inline-flex; align-items:center; gap:6px; background:var(--surface2); border:1px solid var(--border);
    border-radius:99px; padding:5px 12px 5px 10px; margin:3px 6px 3px 0; text-decoration:none; color:var(--text); font-family:var(--mono); font-size:12.5px; }
  .plate-pill:hover { border-color: var(--accent); }
  .plate-pill .n { color: var(--faint); }
  .plate-pill .p { color: var(--good); }
  .plate-pill .dot { width:8px; height:8px; border-radius:50%; display:inline-block; flex:none; }
  .plate-pill.pub-yes { border-color: var(--good); }
  .plate-pill.pub-yes .dot { background: var(--good); }
  .plate-pill.pub-no { border-color: var(--bad); }
  .plate-pill.pub-no .dot { background: var(--bad); }
  .search-controls { display:flex; flex-wrap:wrap; gap:10px 18px; align-items:flex-end; margin-bottom:6px; }
  .search-controls .field { display:flex; flex-direction:column; gap:4px; }
  .search-controls label { font-size:11.5px; color:var(--dim); }
  .search-controls input[type=number] { width:80px; }
  .search-controls input[type=text] { min-width:260px; }
  .search-hit { background:var(--surface2); border:1px solid var(--border); border-radius:8px; margin-bottom:14px; overflow:hidden; }
  .search-hit .hit-group { border-top:1px solid var(--border); }
  .search-hit .hit-group:first-child { border-top:none; }
  .search-hit .hit-head { padding:6px 12px; font-size:11.5px; color:var(--dim); background:var(--surface); }
  .search-hit pre { margin:0; padding:10px 12px; font-family:var(--mono); font-size:12.5px; line-height:1.55;
    white-space:pre-wrap; word-break:break-word; overflow-wrap:anywhere; }
  .search-hit .ln { color:var(--faint); display:inline-block; width:8ch; user-select:none; }
  .search-hit .hit-line { background:#3a3120; }
  .search-hit .hit-line .ln { color:var(--warn); }
</style>
</head>
<body>
<div class="wrap{% if wide %} wide{% endif %}">
<header class="top">
  <h1>🔍 ALPR Log Analyzer</h1>
  <nav>
    <a href="{{ url_for('index') }}">Upload</a>
    {% if file_id %}<a href="{{ url_for('summary', file_id=file_id) }}">Summary</a>
    <a href="{{ url_for('plate_search_page', file_id=file_id) }}">Plate search</a>
    <a href="{{ url_for('text_search_page', file_id=file_id) }}">Text search</a>{% endif %}
  </nav>
</header>
{{ body|safe }}
</div>
</body>
</html>
"""


def render(title, body_html, file_id=None, wide=False):
    return render_template_string(BASE_HTML, title=title, body=body_html, file_id=file_id, wide=wide)


@app.route("/", methods=["GET"])
def index():
    files = list_analyses()
    rows = "".join(
        f'<li><div class="fl-info"><a href="{url_for("summary", file_id=f["id"])}"><strong>{f["name"]}</strong></a> '
        f'<span class="muted">— {f["lines"]:,} lines, {f["first_ts"]} → {f["last_ts"]}</span></div>'
        f'<form class="inline-form" action="{url_for("delete_analysis", file_id=f["id"])}" method="post" '
        f'onsubmit="return confirm(\'Delete this analysis? This cannot be undone.\')">'
        f'<button type="submit" class="link-danger">Delete</button></form></li>'
        for f in files
    )
    delete_all_btn = (
        f'<form action="{url_for("delete_all_analyses")}" method="post" style="margin:10px 0 0" '
        f'onsubmit="return confirm(\'Delete ALL analyzed logs from data/? This cannot be undone.\')">'
        f'<button type="submit" class="btn-danger">Delete all analyzed logs</button></form>'
        if files else ""
    )
    body = f"""
    <form class="upload" action="{url_for('upload')}" method="post" enctype="multipart/form-data">
      <p style="margin-top:0">Upload an ALPR log file — a decompressed .txt/.log file, or a raw
      NanoLog binary file (e.g. <code>nano_logs_EMS-DevServer_...</code>). Binary files are
      decompressed automatically.</p>
      <input type="file" name="logfile" required>
      <div style="margin-top:16px"><button type="submit">Upload &amp; analyze</button></div>
      <p class="muted" style="margin-top:14px">Large files (100MB+) may take a little while to parse — the page will redirect once it's done.</p>
    </form>
    <h2>Previously analyzed files</h2>
    <ul class="filelist">{rows or '<li class="muted">Nothing uploaded yet.</li>'}</ul>
    {delete_all_btn}
    """
    return render("Upload", body)


@app.route("/delete/<file_id>", methods=["POST"])
def delete_analysis(file_id):
    _silent_remove(os.path.join(DATA_DIR, f"{file_id}.json"))
    _silent_remove(raw_log_path_for(file_id))
    return redirect(url_for("index"))


@app.route("/delete-all", methods=["POST"])
def delete_all_analyses():
    for fn in os.listdir(DATA_DIR):
        _silent_remove(os.path.join(DATA_DIR, fn))
    return redirect(url_for("index"))


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("logfile")
    if not f or not f.filename:
        return redirect(url_for("index"))
    file_id = uuid.uuid4().hex[:12]
    saved_path = os.path.join(DATA_DIR, f"{file_id}_raw.txt")
    f.save(saved_path)

    with open(saved_path, "rb") as fchk:
        head = fchk.read(8192)

    decoded_path = None
    source_note = None
    if _looks_like_log_text(head):
        parse_path = saved_path
    else:
        decoded_path, err = decompress_nano_log(saved_path)
        if decoded_path is None:
            _silent_remove(saved_path)
            body = f"""
            <h2>Couldn't read "{f.filename}"</h2>
            <p>{err}</p>
            <p class="muted">This tool accepts already-decompressed ALPR log text files, or raw
            NanoLog binary files (like <code>nano_logs_EMS-DevServer_...</code>) — those are
            decompressed automatically on upload.</p>
            <p><a href="{url_for('index')}">&larr; Back</a></p>
            """
            return render("Upload failed", body)
        parse_path = decoded_path
        source_note = "Decompressed from a NanoLog binary file"

    t0 = time.time()
    analysis = parse_log(parse_path)
    elapsed = time.time() - t0
    analysis["summary"]["parse_seconds"] = round(elapsed, 2)
    if source_note:
        analysis["summary"]["source_note"] = source_note
    save_analysis(file_id, f.filename, analysis)

    # Keep the plain-text log around (renamed into data/) so the log-text
    # search / head / tail feature can read it later — only the raw upload
    # itself (and, for nano files, the original binary) gets discarded.
    try:
        os.replace(parse_path, raw_log_path_for(file_id))
    except OSError:
        pass
    if parse_path != saved_path:
        _silent_remove(saved_path)
    return redirect(url_for("summary", file_id=file_id))


def sev_badge(sev):
    return f'<span class="badge sev-{sev}">{sev.upper()}</span>'


@app.route("/summary/<file_id>")
def summary(file_id):
    d = load_analysis(file_id)
    s = d["summary"]

    findings_html = "".join(
        f'<div class="finding">{sev_badge(fnd["severity"])} <span class="title">{fnd["title"]}</span>'
        f'<div class="detail">{fnd["detail"]}</div></div>'
        for fnd in s["findings"]
    ) or '<p class="muted">No issues detected.</p>'

    lvl = s["level_counts"]
    level_stats = "".join(
        f'<div class="stat"><div class="v">{lvl.get(k,0):,}</div><div class="l">{k}</div></div>'
        for k in ["DEBUG", "NOTICE", "WARNING", "ERROR", "CRITICAL", "FATAL"] if k in lvl
    )

    ch = s["channels"]
    pub = s["publish"]
    fps = s["fps"]
    gst = s["gst"]

    stat_grid = f"""
    <div class="grid">
      <div class="stat"><div class="v">{ch['create_requests']}</div><div class="l">create requests</div></div>
      <div class="stat"><div class="v">{ch['delete_requests']}</div><div class="l">delete requests</div></div>
      <div class="stat"><div class="v">{ch['removed_ok']}</div><div class="l">channels removed ok</div></div>
      <div class="stat"><div class="v">{ch['rejected_deletes']}</div><div class="l">rejected deletes</div></div>
      <div class="stat"><div class="v">{ch['peak_active_tasks'] if ch['peak_active_tasks'] is not None else '—'}</div><div class="l">peak active tasks</div></div>
      <div class="stat"><div class="v">{pub['results']}</div><div class="l">publish attempts</div></div>
      <div class="stat"><div class="v">{pub['distinct_plates']}</div><div class="l">distinct plates</div></div>
      <div class="stat"><div class="v" style="color:var(--good)">{pub['distinct_plates_published']}</div><div class="l">plates published to RocketMQ</div></div>
      <div class="stat"><div class="v">{pub['send_fail']}</div><div class="l">broker send failures</div></div>
      <div class="stat"><div class="v">{('%.1f' % fps['avg']) if fps['avg'] else '—'}</div><div class="l">avg fps</div></div>
      <div class="stat"><div class="v">{gst['connect_failures']}</div><div class="l">gst connect failures</div></div>
      <div class="stat"><div class="v">{gst['read_timeouts']}</div><div class="l">read timeouts</div></div>
      <div class="stat"><div class="v">{s['keepalive_fail_count']}</div><div class="l">keepalive failures</div></div>
    </div>
    """

    def type_table(rows, title):
        body_rows = "".join(
            f'<tr><td class="mono">{r["count"]}×</td><td class="mono" style="white-space:pre-wrap">{r["msg"]}</td>'
            f'<td class="mono muted">{r["ts"]}</td></tr>'
            for r in rows
        )
        if not rows:
            return ""
        return f"""<h3>{title}</h3><table><tr><th>Count</th><th>Message type</th><th>First seen</th></tr>{body_rows}</table>"""

    body = f"""
    <p class="muted">{d['name']} · {s['total_lines']:,} lines · {s['file_first_ts']} → {s['file_last_ts']}
    {' · docker tag ' + s['docker_tag'] if s.get('docker_tag') else ''} · parsed in {s.get('parse_seconds','?')}s
    {' · <span style="color:var(--accent)">' + s['source_note'] + '</span>' if s.get('source_note') else ''}</p>

    <h2>Pipeline health</h2>
    {findings_html}

    <h2>At a glance</h2>
    {stat_grid}

    <h2>Log levels</h2>
    <div class="grid">{level_stats}</div>

    {type_table(s['error_types'], 'Error types')}
    {type_table(s['warn_types'], 'Warning types')}

    <h2>Search a plate number</h2>
    <form action="{url_for('plate_search_page', file_id=file_id)}" method="get" style="margin-top:8px">
      <input type="text" name="q" placeholder="e.g. 8091XKH" autocomplete="off">
      <button type="submit" class="secondary">Track this plate</button>
    </form>

    <h2>Search log text</h2>
    <p class="muted" style="margin-top:-6px">Search for any text in the raw log lines (not just plate numbers), with
    lines of context before/after, or jump to the head/tail of the file.</p>
    <form action="{url_for('text_search_page', file_id=file_id)}" method="get" style="margin-top:8px">
      <input type="text" name="q" placeholder="e.g. Timeout elapsed" autocomplete="off">
      <button type="submit" class="secondary">Search log text</button>
    </form>
    """
    return render(d["name"], body, file_id=file_id)


@app.route("/plate/<file_id>")
def plate_search_page(file_id):
    d = load_analysis(file_id)
    q = request.args.get("q", "").strip().upper()
    plates = d["plates"]

    body = f"""
    <h2>Track a plate</h2>
    <form action="{url_for('plate_search_page', file_id=file_id)}" method="get">
      <input type="text" name="q" placeholder="e.g. 8091XKH" value="{q}" autocomplete="off">
      <button type="submit">Search</button>
    </form>
    """

    if q:
        if q in plates:
            evs = plates[q]
            published_evs = [e for e in evs if e["stage"] == "publish result"]
            if any("confirmed" in e["detail"] for e in published_evs):
                verdict = ('<span class="out-published">✔ Published — confirmed sent to broker</span>')
            elif any("FAILED" in e["detail"] for e in published_evs):
                verdict = ('<span class="out-failed">✘ Publish attempted but broker send FAILED</span>')
            elif any("discarded" in e["stage"] for e in evs):
                verdict = ('<span class="out-failed">✘ Discarded by validity gate — never reached publish</span>')
            elif any(e["stage"] == "published" for e in evs):
                verdict = ('<span class="out-unknown">? Result assembled — send outcome not found nearby</span>')
            else:
                verdict = ('<span class="out-unknown">? Detected only — no completed/published track found</span>')

            items = "".join(
                f'<div class="tl-item" style="--dot-color:{stage_color(e["stage"], e["detail"])}">'
                f'<div class="tl-ts">{e["ts"]}</div>'
                f'<div class="tl-stage" style="background:{stage_color(e["stage"], e["detail"])}22; color:{stage_color(e["stage"], e["detail"])}">{e["stage"]}</div>'
                f'<div class="tl-detail">{e["detail"]}</div></div>'
                for e in evs
            )

            # --- right-side summary counts ---
            stage_counts = Counter(e["stage"] for e in evs)
            detected_n = stage_counts.get("detected", 0)
            published_confirmed = sum(1 for e in published_evs if "confirmed" in e["detail"])
            published_failed = sum(1 for e in published_evs if "FAILED" in e["detail"])
            published_unknown = sum(1 for e in published_evs if "confirmed" not in e["detail"] and "FAILED" not in e["detail"])
            publish_attempts = stage_counts.get("published", 0)

            def count_row(stage_label, count, color):
                if count == 0:
                    return ""
                return (f'<div class="count-row"><span class="label">'
                        f'<span class="dot" style="background:{color}"></span>{stage_label}</span>'
                        f'<span class="num">{count}</span></div>')

            sidebar_rows = "".join([
                count_row("Detected (raw frames)", detected_n, STAGE_COLORS["detected"]),
                count_row("Classified", stage_counts.get("classified", 0), STAGE_COLORS["classified"]),
                count_row("Classified (after threshold)", stage_counts.get("classified (after threshold)", 0), STAGE_COLORS["classified (after threshold)"]),
                count_row("Tracks started", stage_counts.get("track started", 0), STAGE_COLORS["track started"]),
                count_row("Track matches", stage_counts.get("track matched", 0), STAGE_COLORS["track matched"]),
                count_row("Track relabeled", stage_counts.get("track relabeled", 0), STAGE_COLORS["track relabeled"]),
                count_row("Tracks ended", stage_counts.get("track ended", 0), STAGE_COLORS["track ended"]),
                count_row("Validity passed", stage_counts.get("validity check (passed)", 0), STAGE_COLORS["validity check (passed)"]),
                count_row("Validity failed (discarded)", stage_counts.get("validity check (failed — discarded)", 0), STAGE_COLORS["validity check (failed — discarded)"]),
                count_row("Pushed to publisher", stage_counts.get("track pushed to publisher", 0), STAGE_COLORS["track pushed to publisher"]),
                count_row("Channel assigned", stage_counts.get("channel assigned", 0), STAGE_COLORS["channel assigned"]),
            ])

            # --- similar plates: same length, 1-2 characters different ---
            close_plates = find_close_plates(q, plates.keys())
            if close_plates:
                pill_parts = []
                for cp in close_plates:
                    cp_detected = sum(1 for e in plates[cp] if e["stage"] == "detected")
                    cp_pub = plate_is_published(plates[cp])
                    pub_class = "pub-yes" if cp_pub else "pub-no"
                    link = url_for("plate_search_page", file_id=file_id, q=cp)
                    pill_parts.append(
                        f'<a class="plate-pill {pub_class}" href="{link}"><span class="dot"></span>{cp} <span class="n">{cp_detected}×</span></a>'
                    )
                similar_html = (
                    '<div class="card"><h3 style="margin-top:0">Similar plates</h3>'
                    '<p class="muted" style="margin-top:-4px">Same length, 1-2 characters different — likely the same '
                    'vehicle misread. <span style="color:var(--good)">●</span> published to RocketMQ, '
                    f'<span style="color:var(--bad)">●</span> not published.</p>{"".join(pill_parts)}</div>'
                )
            else:
                similar_html = ""

            body += f"""
            <h2>Plate {q} <span style="font-size:14px; font-weight:400">— {len(evs)} events</span></h2>
            <p style="font-size:15px">{verdict}</p>
            <div class="plate-layout">
              <div class="timeline">{items}</div>
              <aside class="side-summary">
                <div class="card verdict-card">
                  <div class="headline-stats">
                    <div class="stat"><div class="v" style="color:{STAGE_COLORS['detected']}">{detected_n}</div><div class="l">times detected</div></div>
                    <div class="stat"><div class="v" style="color:{STAGE_COLORS['published']}">{publish_attempts}</div><div class="l">publish attempts</div></div>
                  </div>
                  {count_row("Published (confirmed)", published_confirmed, "#5fbf7a")}
                  {count_row("Publish failed", published_failed, "#c46b62")}
                  {count_row("Publish outcome unknown", published_unknown, "#93a1b4")}
                </div>
                <div class="card">
                  <h3 style="margin-top:0">Event breakdown</h3>
                  {sidebar_rows}
                </div>
                {similar_html}
              </aside>
            </div>
            """
        else:
            substring_candidates = [p for p in plates.keys() if q and (q in p or p in q)]
            close_candidates = find_close_plates(q, plates.keys())
            seen = set()
            candidates = []
            for c in close_candidates + substring_candidates:
                if c not in seen:
                    seen.add(c)
                    candidates.append(c)
            candidates = candidates[:20]
            cand_html = "".join(
                f'<li><a href="{url_for("plate_search_page", file_id=file_id, q=c)}">{c}</a> '
                f'<span class="muted">({sum(1 for e in plates[c] if e["stage"]=="detected")} detections)</span></li>'
                for c in candidates
            )
            body += f"""
            <h2>No exact match for "{q}"</h2>
            {'<p>Similar plates found in this log (same length &amp; close text, or containing your search):</p><ul>' + cand_html + '</ul>' if candidates else '<p class="muted">No similar plates found either — OCR reads with unclear characters show as dashes (e.g. 6087J--), try a shorter fragment.</p>'}
            """

    return render(f"Plate {q}" if q else "Plate search", body, file_id=file_id)


@app.route("/textsearch/<file_id>")
def text_search_page(file_id):
    d = load_analysis(file_id)
    raw_path = raw_log_path_for(file_id)
    has_raw = os.path.isfile(raw_path)

    q = request.args.get("q", "").strip()
    mode = request.args.get("mode") or ("search" if q else "")

    def _int_arg(name, default, lo, hi):
        try:
            v = int(request.args.get(name, default))
        except (TypeError, ValueError):
            v = default
        return max(lo, min(v, hi))

    before = _int_arg("before", 3, 0, 500)
    after = _int_arg("after", 3, 0, 500)
    n = _int_arg("n", 200, 1, 5000)

    controls = f"""
    <div class="card">
      <form method="get">
        <input type="hidden" name="mode" value="search">
        <div class="search-controls">
          <div class="field"><label>Search text</label>
            <input type="text" name="q" value="{esc(q)}" placeholder="e.g. Timeout elapsed" autocomplete="off"></div>
          <div class="field"><label>Lines before</label><input type="number" name="before" value="{before}" min="0" max="500"></div>
          <div class="field"><label>Lines after</label><input type="number" name="after" value="{after}" min="0" max="500"></div>
          <div class="field"><button type="submit">Search</button></div>
        </div>
      </form>
      <form method="get" style="margin-top:10px">
        <input type="hidden" name="q" value="{esc(q)}">
        <input type="hidden" name="before" value="{before}">
        <input type="hidden" name="after" value="{after}">
        <div class="search-controls">
          <div class="field"><label>Number of lines</label><input type="number" name="n" value="{n}" min="1" max="5000"></div>
          <div class="field"><button type="submit" name="mode" value="head" class="secondary">Head — first N lines</button></div>
          <div class="field"><button type="submit" name="mode" value="tail" class="secondary">Tail — last N lines</button></div>
        </div>
      </form>
    </div>
    """

    if not has_raw:
        body = f"""
        <h2>Search log text — {d['name']}</h2>
        {controls}
        <p class="muted">The raw log text for this file isn't available (it was analyzed before this
        feature was added — re-upload the file to enable text search).</p>
        """
        return render("Search log text", body, file_id=file_id, wide=True)

    def render_lines_block(title, rows):
        if not rows:
            return '<p class="muted">File is empty.</p>'
        body_lines = "".join(f'<div><span class="ln">{ln}</span>{esc(txt)}</div>' for ln, txt in rows)
        return f'<div class="search-hit"><div class="hit-group"><div class="hit-head">{title}</div><pre>{body_lines}</pre></div></div>'

    result_html = ""
    if mode == "head":
        rows = head_lines(raw_path, n)
        result_html = render_lines_block(f"First {len(rows)} lines", rows)
    elif mode == "tail":
        rows = tail_lines(raw_path, n)
        result_html = render_lines_block(f"Last {len(rows)} lines", rows)
    elif mode == "search" and q:
        blocks, truncated = search_text_lines(raw_path, q, before, after)
        if not blocks:
            result_html = '<p class="muted">No matches found.</p>'
        else:
            groups = []
            for blk in blocks:
                lines_html = "".join(
                    f'<div class="{"hit-line" if is_m else ""}"><span class="ln">{ln}</span>{esc(txt)}</div>'
                    for ln, txt, is_m in blk["lines"]
                )
                groups.append(
                    f'<div class="hit-group"><div class="hit-head">line {blk["match_line"]}</div><pre>{lines_html}</pre></div>'
                )
            result_html = (
                f'<p class="muted">{len(blocks)} match{"es" if len(blocks) != 1 else ""}'
                f'{" — stopped early, refine your search for the rest" if truncated else ""}</p>'
                f'<div class="search-hit">{"".join(groups)}</div>'
            )
    elif mode == "search" and not q:
        result_html = '<p class="muted">Type something to search for.</p>'

    body = f"""
    <h2>Search log text — {d['name']}</h2>
    <p class="muted" style="margin-top:-6px">Search any text across the raw log lines, with context lines
    before/after each hit, or jump straight to the head/tail of the file.</p>
    {controls}
    {result_html}
    """
    return render("Search log text", body, file_id=file_id, wide=True)


@app.route("/api/plates/<file_id>")
def api_plates(file_id):
    d = load_analysis(file_id)
    return jsonify(sorted(d["plates"].keys()))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    print(f"ALPR Log Analyzer running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
