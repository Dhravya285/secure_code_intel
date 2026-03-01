"""
app.py  —  SCIE Backend
────────────────────────
pip install flask flask-cors
python app.py
open http://localhost:5000
"""
import os, uuid, threading, tempfile, shutil
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="ui")
CORS(app)
JOBS = {}


# ── helpers ───────────────────────────────────────────────────────────────────

def new_job(mode, filenames):
    jid = str(uuid.uuid4())[:8]
    JOBS[jid] = dict(id=jid, mode=mode, status="queued", progress=0,
                     step="Queued…", log=[], filenames=filenames,
                     findings=[], clusters=[], metrics={}, error=None)
    return jid


def log(jid, msg):
    JOBS[jid]["log"].append(msg)
    JOBS[jid]["step"] = msg


def save_files(files):
    d, saved = tempfile.mkdtemp(prefix="scie_"), []
    for f in files:
        name = Path(f.filename).name
        if name.endswith(".py"):
            f.save(os.path.join(d, name)); saved.append(name)
    return d, saved


# ── static pipeline ───────────────────────────────────────────────────────────

def run_static(jid, tmpdir):
    job = JOBS[jid]
    try:
        job["status"] = "running"
        from scanner.ast_scanner      import scan_file
        from scanner.feature_engineer import engineer_all
        from scoring.risk_scorer      import score_all
        from prioritization.aggregator     import build_clusters
        from prioritization.cluster_scorer import score_and_rank_clusters

        log(jid, "Parsing source files…");         job["progress"] = 10
        raw = [r for f in Path(tmpdir).glob("*.py") for r in scan_file(str(f))]

        if not raw:
            job.update(status="done", progress=100, step="No vulnerabilities found."); return

        log(jid, f"{len(raw)} signals — feature engineering…"); job["progress"] = 35
        enriched = engineer_all(raw)

        log(jid, "Static risk scoring…");           job["progress"] = 60
        scored = score_all(enriched)
        scored.sort(key=lambda x: x["static_risk_score"], reverse=True)
        for s in scored:
            s.setdefault("final_risk", s["static_risk_score"])

        log(jid, "Clustering findings…");           job["progress"] = 82
        ranked = score_and_rank_clusters(build_clusters(scored))
        clean  = [{k:v for k,v in c.items() if k != "findings"} for c in ranked]

        job.update(findings=scored, clusters=clean, status="done", progress=100,
                   step=f"Done — {len(scored)} findings · {len(clean)} clusters")
    except Exception as e:
        job.update(status="error", error=str(e), step=f"ERROR: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── full pipeline (LLM) ───────────────────────────────────────────────────────

def run_full(jid, tmpdir):
    job = JOBS[jid]
    try:
        job["status"] = "running"
        from scanner.ast_scanner      import scan_file
        from scanner.feature_engineer import engineer_all
        from scoring.risk_scorer      import score_all
        from scoring.hybrid_scorer    import enrich_with_hybrid_score
        from llm.prompt_templates     import build_vuln_prompt
        from llm.llm_client           import call_llm
        from llm.patch_validator      import validate_patch
        from prioritization.aggregator         import build_clusters
        from prioritization.cluster_scorer     import score_and_rank_clusters
        from prioritization.business_explainer import explain_top_clusters

        log(jid, "Parsing source files…");  job["progress"] = 5
        raw = [r for f in Path(tmpdir).glob("*.py") for r in scan_file(str(f))]

        if not raw:
            job.update(status="done", progress=100, step="No vulnerabilities found."); return

        log(jid, f"{len(raw)} signals — feature engineering…"); job["progress"] = 12
        scored = score_all(engineer_all(raw))
        total  = len(scored)

        finals = []
        for i, finding in enumerate(scored):
            job["progress"] = 20 + int((i / total) * 55)
            log(jid, f"LLM [{i+1}/{total}] {finding['type']} · {Path(finding['file']).name}")
            resp  = call_llm(build_vuln_prompt(finding), retries=1)
            final = enrich_with_hybrid_score(finding, resp, validate_patch(finding, resp))
            finals.append(final)

        finals.sort(key=lambda x: x["final_risk"], reverse=True)

        log(jid, "Clustering…");            job["progress"] = 78
        ranked = score_and_rank_clusters(build_clusters(finals))

        log(jid, "Business explanations…"); job["progress"] = 90
        ranked = explain_top_clusters(ranked, top_n=3)
        clean  = [{k:v for k,v in c.items() if k != "findings"} for c in ranked]

        validated = sum(1 for f in finals if f.get("validated"))
        metrics   = dict(total=len(finals), validated=validated,
                         patch_rate=round(validated/len(finals),3) if finals else 0,
                         avg_final_risk=round(sum(f["final_risk"] for f in finals)/len(finals),4))

        job.update(findings=finals, clusters=clean, metrics=metrics, status="done",
                   progress=100, step=f"Done — {len(finals)} findings · {len(clean)} clusters · {validated}/{len(finals)} patches validated")
    except Exception as e:
        job.update(status="error", error=str(e), step=f"ERROR: {e}")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index(): return send_from_directory("ui", "index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    files = request.files.getlist("files")
    if not files: return jsonify(error="No files"), 400
    tmpdir, names = save_files(files)
    mode = request.form.get("mode", "static")
    jid  = new_job(mode, names)
    threading.Thread(target=run_static if mode=="static" else run_full,
                     args=(jid, tmpdir), daemon=True).start()
    return jsonify(job_id=jid)

@app.route("/api/status/<jid>")
def status(jid):
    job = JOBS.get(jid)
    if not job: return jsonify(error="Not found"), 404
    if job["status"] == "done": return jsonify(job)
    return jsonify({k:v for k,v in job.items() if k not in ("findings","clusters")})

if __name__ == "__main__":
    os.makedirs("ui", exist_ok=True)
    print("\n  SCIE  →  http://localhost:5000\n")
    app.run(debug=False, port=5000, threaded=True)