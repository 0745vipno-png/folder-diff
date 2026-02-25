import argparse
import csv
import hashlib
import json
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


TOOL_NAME = "folder-diff"
TOOL_VERSION = "1.0.0"


# -------------------------
# Utils
# -------------------------
def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def local_now_compact() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# -------------------------
# Auditor
# -------------------------
class Auditor:
    def __init__(self, path: Path):
        self.path = path
        self.fp = path.open("a", encoding="utf-8", newline="\n")

    def log(self, level: str, msg: str):
        line = f"{utc_now_iso()} [{level}] {msg}"
        print(line)
        self.fp.write(line + "\n")
        self.fp.flush()

    def close(self):
        self.fp.flush()
        self.fp.close()


# -------------------------
# Data models
# -------------------------
@dataclass
class DiffRecord:
    type: str  # ADDED / REMOVED / MODIFIED
    rel_path: str
    changed_fields: Optional[List[str]]
    a: Optional[dict]
    b: Optional[dict]


# -------------------------
# Snapshot loader
# -------------------------
def load_snapshot(path: Path, auditor: Auditor) -> dict:
    auditor.log("INFO", f"load_snapshot path='{path}'")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        auditor.log("ERROR", f"snapshot_read_failed {type(e).__name__}: {e}")
        raise


def build_file_index(snapshot: dict) -> Dict[str, dict]:
    index = {}
    for e in snapshot.get("entries", []):
        if e.get("kind") == "file":
            index[e["rel_path"]] = e
    return index


# -------------------------
# Integrity (audit mode)
# -------------------------
def verify_integrity(snapshot_path: Path, manifest_path: Optional[Path], auditor: Auditor) -> str:
    if not manifest_path or not manifest_path.exists():
        auditor.log("WARN", "manifest_missing integrity_status=UNKNOWN")
        return "UNKNOWN"

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        auditor.log("WARN", f"manifest_parse_failed {e}")
        return "UNKNOWN"

    artifacts = manifest.get("artifacts", {})
    snap_info = artifacts.get("snapshot_json")
    if not snap_info:
        auditor.log("WARN", "manifest_no_snapshot_entry integrity_status=UNKNOWN")
        return "UNKNOWN"

    expected = snap_info.get("sha256")
    actual = sha256_file(snapshot_path)
    if expected == actual:
        auditor.log("INFO", "integrity_ok")
        return "OK"
    else:
        auditor.log("WARN", "integrity_failed hash_mismatch")
        return "FAILED"


# -------------------------
# Diff engine (smart mode)
# -------------------------
def diff_entries(a_index: Dict[str, dict], b_index: Dict[str, dict], auditor: Auditor) -> Tuple[List[DiffRecord], dict]:
    records: List[DiffRecord] = []

    a_keys = set(a_index.keys())
    b_keys = set(b_index.keys())

    added = b_keys - a_keys
    removed = a_keys - b_keys
    common = a_keys & b_keys

    for k in sorted(added):
        records.append(DiffRecord("ADDED", k, None, None, b_index[k]))

    for k in sorted(removed):
        records.append(DiffRecord("REMOVED", k, None, a_index[k], None))

    modified_count = 0

    for k in sorted(common):
        a = a_index[k]
        b = b_index[k]

        changed_fields = []

        # SMART: prefer hash if both have sha256
        if a.get("sha256") and b.get("sha256"):
            if a["sha256"] != b["sha256"]:
                changed_fields.append("sha256")
        else:
            # fallback
            if a.get("size") != b.get("size"):
                changed_fields.append("size")
            if a.get("mtime_epoch") != b.get("mtime_epoch"):
                changed_fields.append("mtime_epoch")

        if changed_fields:
            modified_count += 1
            records.append(DiffRecord("MODIFIED", k, changed_fields, a, b))

    summary = {
        "added": len(added),
        "removed": len(removed),
        "modified": modified_count,
        "total_changed": len(records),
    }

    return records, summary


# -------------------------
# Writers
# -------------------------
def write_json(path: Path, payload: dict):
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(path: Path, records: List[DiffRecord]):
    fieldnames = ["type", "rel_path", "changed_fields"]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in records:
            w.writerow({
                "type": r.type,
                "rel_path": r.rel_path,
                "changed_fields": ",".join(r.changed_fields or []),
            })


def write_manifest(path: Path, artifacts: Dict[str, Path], run_id: str):
    items = {}
    for name, p in artifacts.items():
        items[name] = {
            "path": str(p),
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
        }

    manifest = {
        "manifest_version": 1,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "run_id": run_id,
        "generated_at_utc": utc_now_iso(),
        "artifacts": items,
    }
    write_json(path, manifest)


# -------------------------
# CLI
# -------------------------
def parse_args(argv):
    ap = argparse.ArgumentParser(description="One-shot snapshot diff tool (smart hash-first mode)")
    ap.add_argument("--a", required=True, help="Snapshot A JSON path")
    ap.add_argument("--b", required=True, help="Snapshot B JSON path")
    ap.add_argument("--out", default="diff_out", help="Output folder")
    ap.add_argument("--manifest-a", help="Optional manifest for snapshot A")
    ap.add_argument("--manifest-b", help="Optional manifest for snapshot B")
    return ap.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    run_id = local_now_compact()

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    log_path = out_dir / f"audit_{run_id}.log"
    auditor = Auditor(log_path)

    auditor.log("INFO", f"start tool={TOOL_NAME} version={TOOL_VERSION} run_id={run_id}")

    a_path = Path(args.a).resolve()
    b_path = Path(args.b).resolve()

    if not a_path.exists() or not b_path.exists():
        auditor.log("ERROR", "snapshot_path_missing")
        auditor.close()
        return 1

    # Integrity (audit mode)
    integrity_a = verify_integrity(a_path, Path(args.manifest_a) if args.manifest_a else None, auditor)
    integrity_b = verify_integrity(b_path, Path(args.manifest_b) if args.manifest_b else None, auditor)

    snap_a = load_snapshot(a_path, auditor)
    snap_b = load_snapshot(b_path, auditor)

    index_a = build_file_index(snap_a)
    index_b = build_file_index(snap_b)

    records, summary = diff_entries(index_a, index_b, auditor)

    payload = {
        "header": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "run_id": run_id,
            "mode": "smart",
            "integrity": {
                "snapshot_a": integrity_a,
                "snapshot_b": integrity_b,
            },
        },
        "summary": summary,
        "records": [asdict(r) for r in records],
    }

    json_path = out_dir / f"diff_{run_id}.json"
    csv_path = out_dir / f"diff_{run_id}.csv"
    manifest_path = out_dir / f"manifest_{run_id}.json"

    write_json(json_path, payload)
    write_csv(csv_path, records)

    write_manifest(
        manifest_path,
        artifacts={
            "diff_json": json_path,
            "diff_csv": csv_path,
            "audit_log": log_path,
        },
        run_id=run_id,
    )

    auditor.log("INFO", f"done added={summary['added']} removed={summary['removed']} modified={summary['modified']}")
    auditor.close()

    # exit code policy
    if integrity_a == "FAILED" or integrity_b == "FAILED":
        return 2
    if summary["total_changed"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))