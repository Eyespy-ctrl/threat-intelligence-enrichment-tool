# app.py
import os
import csv
import io
from datetime import datetime
from dotenv import load_dotenv

from flask import (
    Flask, render_template, request, redirect, url_for, flash, Response
)
from sqlalchemy import text

# Local modules - ensure these exist in your project
from database import db, Observable
from enrich import enrich_observable

load_dotenv()

# ------------------------
# Flask + DB configuration
# ------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
db_path = os.getenv("DATABASE_PATH", "ti_tool.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.abspath(db_path)}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


# ------------------------
# Helper: ensure DB + created_at column
# ------------------------
def ensure_tables_and_columns():
    """
    Create tables and ensure observables.created_at exists. If created_at is missing,
    ALTER TABLE to add it and backfill existing rows.
    """
    # create tables from models (no-op if exists)
    db.create_all()

    engine = db.engine
    with engine.begin() as conn:
        # Check if observables table is present
        r = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='observables';")
        ).fetchone()
        if not r:
            # table not present (shouldn't happen after create_all), guard anyway
            return

        # Check columns
        cols = conn.execute(text("PRAGMA table_info('observables');")).fetchall()
        col_names = [row[1] for row in cols]
        if "created_at" in col_names:
            return  # already present

        # Add created_at column and backfill existing rows
        try:
            conn.execute(text("ALTER TABLE observables ADD COLUMN created_at DATETIME;"))
            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(
                text("UPDATE observables SET created_at = :now WHERE created_at IS NULL;"),
                {"now": now}
            )
            print("[setup] Added created_at column and backfilled rows.")
        except Exception as exc:
            print("[setup] Could not add created_at column:", exc)


with app.app_context():
    ensure_tables_and_columns()


# First, make sure the function is defined somewhere in app.py
def get_severity_class(provider: str, score_str: str) -> str:
    provider_lower = provider.lower()
    if not score_str or score_str in ('-', 'N/A', 'Error', ''):
        return "severity-error"

    try:
        score = float(score_str)
    except (ValueError, TypeError):
        return "severity-error"

    if "abuseipdb" in provider_lower:
        if score >= 70:   return "severity-red"
        if score >= 30:   return "severity-yellow"
        return "severity-green"

    elif "alienvault" in provider_lower or "otx" in provider_lower:
        if score >= 10:   return "severity-red"
        if score >= 3:    return "severity-yellow"
        return "severity-green"

    elif "virustotal" in provider_lower:
        if score >= 100:  return "severity-green"   # strong positive = good
        if score >= 0:    return "severity-yellow"  # neutral
        return "severity-red"                       # negative = bad

    elif "shodan" in provider_lower:
        # Simple string handling for now
        if "open ports" in score_str:
            try:
                ports = int(score_str.split()[0])
                if ports > 10: return "severity-red"
                if ports > 3:  return "severity-yellow"
            except:
                pass
        return "severity-green"

    return "severity-green" if score >= 0 else "severity-red"


# ──────────────────────────────────────────────────────────────
# Add this to make the function available in ALL templates
# ──────────────────────────────────────────────────────────────
@app.context_processor
def utility_processor():
    return dict(get_severity_class=get_severity_class)

# ------------------------
# Utilities
# ------------------------
def is_ip(value: str) -> bool:
    """Very simple IPv4 check."""
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# ------------------------
# Routes: index / submit / results / all
# ------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/submit", methods=["GET", "POST"])
def submit():
    # GET -> render the form; POST -> process the form
    if request.method == "GET":
        return render_template("index.html")

    value = request.form.get("observable", "").strip()
    if not value:
        flash("Please enter an observable (IP or domain).", "warning")
        return redirect(url_for("submit"))

    obs_type = "ip" if is_ip(value) else "domain"

    try:
        providers = enrich_observable(value, obs_type)
        count = len(providers) if providers else 0
        flash(f"Enrichment completed: {count} provider(s) returned.", "success")
    except Exception as e:
        print("[enrich] exception:", e)
        flash("An error occurred during enrichment. Check server logs.", "danger")

    return redirect(url_for("results", value=value))


@app.route("/results")
def results():
    """
    Show results for ?value=<observable>. If not provided, redirect home.
    """
    value = request.args.get("value", "").strip()
    if not value:
        flash("No observable specified.", "warning")
        return redirect(url_for("index"))

    # Try ordering by created_at (descending). If created_at missing, fallback to unsorted.
    try:
        rows = Observable.query.filter_by(value=value).order_by(Observable.created_at.desc()).all()
    except Exception:
        rows = Observable.query.filter_by(value=value).all()

    return render_template("results.html", observable=value, results=rows)


@app.route("/all")
def all_entries():
    try:
        rows = Observable.query.order_by(Observable.created_at.desc()).all()
    except Exception:
        rows = Observable.query.all()
    return render_template("results.html", observable="All Observables", results=rows)


# ------------------------
# CSV download routes
# ------------------------
@app.route("/download")
def download_csv():
    """
    Download CSV for a single observable specified by ?value=<observable>.
    """
    value = request.args.get("value", "").strip()
    if not value:
        flash("No observable specified for CSV download.", "warning")
        return redirect(url_for("index"))

    rows = Observable.query.filter_by(value=value).order_by(Observable.created_at.desc()).all()

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["id", "type", "value", "provider", "country", "score", "created_at", "details"])

    for r in rows:
        created = r.created_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(r, "created_at", None) else ""
        details = (r.details or "")
        # remove newlines so CSV rows stay intact
        details_flat = details.replace("\n", " ").replace("\r", " ")
        writer.writerow([
            r.id,
            r.type,
            r.value,
            r.provider or "",
            r.country or "",
            r.score or "",
            created,
            details_flat
        ])

    csv_data = si.getvalue()
    si.close()

    safe_name = value.replace("/", "_").replace(" ", "_")
    filename = f"results_{safe_name}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/download_all")
def download_all_csv():
    """
    Download CSV for all observables in the DB.
    """
    rows = Observable.query.order_by(Observable.created_at.desc()).all()

    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["id", "type", "value", "provider", "country", "score", "created_at", "details"])

    for r in rows:
        created = r.created_at.strftime("%Y-%m-%d %H:%M:%S") if getattr(r, "created_at", None) else ""
        details = (r.details or "")
        details_flat = details.replace("\n", " ").replace("\r", " ")
        writer.writerow([
            r.id,
            r.type,
            r.value,
            r.provider or "",
            r.country or "",
            r.score or "",
            created,
            details_flat
        ])

    csv_data = si.getvalue()
    si.close()

    filename = "results_all.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ------------------------
# Run server
# ------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
