# api/

New iEXAM backend. FastAPI + Pydantic v2.

## Layout

- `main.py` — application factory; mounts route modules.
- `routes/` — HTTP route handlers, grouped by mode (`acg/`, future `rg/`, `sg/`) plus cross-mode routes (`health.py`).
- `services/` — business logic. Routes call services; services never import routes.
- `schemas/` — Pydantic request/response models.
- `core/` — cross-cutting: `config.py`, `logging.py`, `errors.py`.
- `tests/` — pytest tests, mirroring the package layout.

## Run locally

From the repo root, with `.iEXAM` venv active:

```bash
python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
```

## Tests

```bash
python -m pytest api/tests -v
```

## Conventions

- Routes are thin: parse input, call a service, return a model. No business logic in `routes/`.
- Errors raise `ApiException` subclasses (see `core/errors.py`); the global handler renders them as `{error: {code, message, details}}` with non-2xx status.
- Logging goes through `core/logging.py` (file at `Logs/log.txt`).
