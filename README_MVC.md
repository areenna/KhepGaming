# KhepGaming — MVC Refactor (Flask)

This refactors the original monolithic `app.py` into a lightweight MVC-style structure using Flask blueprints.

## Layout

```text
khepgaming/
  __init__.py          # app factory, DB lifecycle
  config.py            # configuration & DB credentials (reads env vars)
  controllers/
    main.py            # all routes registered on Blueprint 'main'
  models/
    db.py              # DB connection helpers (mysql.connector)
  templates/           # moved intact from original
  static/              # moved intact from original
run.py                 # dev entry point
requirements.txt
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Set your DB credentials (recommended)
export SECRET_KEY="change-me"
export MYSQL_HOST="127.0.0.1"
export MYSQL_USER="root"
export MYSQL_PASSWORD="areen"
export MYSQL_PORT="3306"
export MYSQL_DB="khepgaming"

python run.py
# open http://localhost:5000
```

## Notes

- Endpoints now live on the `main` blueprint. Existing `url_for(...)` calls in Python and HTML templates were updated to `url_for('main.<endpoint>')` where necessary.
- DB connection lifecycle is centralized in `khepgaming/__init__.py`; each request attaches `g.db` just like your original code.
- Secrets are read from environment variables — stop committing plaintext passwords.
- This refactor focuses on structure (controllers/models separation and app factory). SQL remains inline within controller functions for minimal behavior change. A deeper refactor would move query logic into `models/` modules (e.g., `models/user.py`, `models/booking.py`).

## Next steps (optional, recommended)

- Move per-entity SQL helper functions into `models/*.py` modules and import them in controllers.
- Add teardown error handling and connection pooling.
- Introduce `.env` management (e.g. `python-dotenv`), migrations, and SQLAlchemy if desired.
```
