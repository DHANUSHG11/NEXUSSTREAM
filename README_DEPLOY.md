# NEXUSTREAM quick deployment

## Local
1. Create/activate a virtual environment.
2. `pip install -r requirements.txt`
3. `python app.py`
4. Open `http://127.0.0.1:5000`

## Production
- Set `SECRET_KEY` to a long random secret.
- Set `DATABASE_URL` to a persistent PostgreSQL connection string.
- Set `MEDIA_ROOT` to a persistent disk mount, e.g. `/var/data`.
- Start with `gunicorn app:app`.
- The app serves videos through `/media/videos/...` and profile photos through `/media/profile/...`.

## Recovery
New accounts receive a one-time recovery code on the registration success screen. This is a deadline-friendly recovery mechanism. For a public production system, replace it with an email-based reset flow.
