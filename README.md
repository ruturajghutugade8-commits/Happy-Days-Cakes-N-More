# Cafe Càtta — Flask Café Ordering Platform

A production-oriented Flask + PostgreSQL ordering system for a café, bakery or cake shop.

## Stack
- Python / Flask
- PostgreSQL (Supabase)
- psycopg2 connection pooling
- HTML/CSS/JavaScript
- Gunicorn
- Optional Razorpay Standard Checkout

## Features
- Responsive café storefront
- Product categories and availability
- Cart with quantity updates
- Pickup / delivery checkout
- Pay at café / cash on delivery
- Optional Razorpay online payment with server-side signature verification
- Customer registration, login and order history
- Admin dashboard
- Product CRUD and availability control
- Customer management
- Order status + payment status management
- CSRF protection for forms
- Secure session cookie settings in production
- Security headers
- Database connection pooling
- `/health` endpoint for deployment health checks

## Local setup
1. Create a virtual environment.
2. Install dependencies:
   `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and add Supabase credentials.
4. Run `database.sql` in Supabase SQL Editor.
5. Start locally:
   `python app.py`

## Admin account
Register a normal account first, then in Supabase SQL Editor run:

```sql
UPDATE users SET is_admin = TRUE WHERE email = 'YOUR_ADMIN_EMAIL';
```

The same login page is used for admin accounts. After login, an admin is redirected to `/admin`.

## Render
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --workers 2 --threads 2 --timeout 120`
- Health check: `/health`
- Add all database and secret values as Render environment variables.
- Never upload `.env` to GitHub.

## Payment
Online payment is optional. Add `RAZORPAY_KEY_ID` and `RAZORPAY_KEY_SECRET` in the environment to enable Razorpay. The server creates a Razorpay order and verifies the returned signature before marking an order as paid. See the official Razorpay Standard Checkout documentation for test/live setup.

## Production notes
A free Render web service can sleep after inactivity, so it is suitable for demos but not a strong choice for a client-facing production workload. For a real café, use an always-on paid web service, a custom domain, real product photos, backups, monitoring and a payment gateway account.
