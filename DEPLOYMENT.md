# Cafe Càtta Deployment Checklist

## 1. Supabase
Run `database.sql` in the Supabase SQL Editor. It is designed to migrate the existing tables by adding the new catalogue/order/payment fields.

Create/confirm an admin account:
```sql
UPDATE users SET is_admin = TRUE WHERE email = 'YOUR_ADMIN_EMAIL';
```

## 2. Render environment variables
Set:
- `SECRET_KEY` — long random secret
- `FLASK_ENV=production`
- `FLASK_DEBUG=false`
- `DB_HOST` — Supabase Session Pooler host
- `DB_PORT=5432`
- `DB_USER` — Supabase Session Pooler user
- `DB_PASSWORD` — current database password
- `DB_NAME=postgres`
- `DB_SSLMODE=require`
- `DB_POOL_MAX=5`

Optional online payments:
- `RAZORPAY_KEY_ID`
- `RAZORPAY_KEY_SECRET`

## 3. Render commands
Build:
```bash
pip install -r requirements.txt
```

Start:
```bash
gunicorn app:app --workers 2 --threads 2 --timeout 120
```

Health check:
```text
/health
```

## 4. Production
Free Render is suitable for demos but can sleep after inactivity. For a café client, use an always-on paid web service and connect a custom domain.

Use real café product images rather than demo Unsplash images before launch.

## 5. Payment
If Razorpay keys are not configured, checkout offers Pay at Café / Cash on Delivery only. If keys are configured, the online payment option creates a server-side Razorpay order and verifies the returned payment signature before marking the order paid.
