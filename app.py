from flask import Flask, abort, jsonify, render_template, request

from enrichment import DEFAULT_IOCS, parse_iocs_from_text, run_enrichment
from log_parser import enrich_cases_with_report, parse_log

app = Flask(__name__)


def get_dashboard_data():
    data = parse_log()
    data["cases"] = enrich_cases_with_report(data["cases"])
    data["open_count"] = sum(
        1 for c in data["cases"] if c["status"] in ("open", "investigating")
    )
    return data


def get_case(case_id):
    for case in get_dashboard_data()["cases"]:
        if case["id"] == case_id:
            return case
    return None


@app.route("/")
def index():
    data = get_dashboard_data()
    return render_template(
        "index.html",
        stats=data["stats"],
        cases=data["cases"],
        events=data["events"][:15],
        open_count=data["open_count"],
    )


@app.route("/case/<case_id>")
def case_detail(case_id):
    data = get_dashboard_data()
    case = get_case(case_id)
    if not case:
        abort(404)
    return render_template("case.html", case=case, stats=data["stats"])


@app.route("/api/events")
def api_events():
    data = parse_log()
    return jsonify(data["events"])


@app.route("/api/stats")
def api_stats():
    data = parse_log()
    return jsonify(data["stats"])


@app.route("/triage")
def triage_page():
    data = get_dashboard_data()
    default_text = "\n".join(
        DEFAULT_IOCS["ip_addresses"]
        + DEFAULT_IOCS["domains"]
        + DEFAULT_IOCS["urls"]
    )
    return render_template(
        "triage.html",
        stats=data["stats"],
        default_iocs=default_text,
    )


@app.route("/api/enrich", methods=["POST"])
def api_enrich():
    body = request.get_json(silent=True) or {}
    raw = body.get("iocs", "") or body.get("text", "")
    use_lab = body.get("use_lab_defaults", False)

    if use_lab:
        iocs = DEFAULT_IOCS
    elif raw.strip():
        iocs = parse_iocs_from_text(raw)
        if not any(iocs.values()):
            return jsonify({"error": "No IOCs found in input"}), 400
    else:
        return jsonify({"error": "Provide IOCs text or use_lab_defaults"}), 400

    save = body.get("save_report", True)
    out = run_enrichment(iocs, save=save)
    return jsonify({
        "results": out["results"],
        "high_count": out["high_count"],
        "timestamp": out["report"]["report_timestamp"],
        "saved": save,
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
