# BPI Commercial LLC website

Live site: https://bpicommercial.org (hosted on Netlify, deployed automatically from this repository).

## What's in here

| Folder / file | What it is |
|---|---|
| `site/` | The website itself. Everything in this folder is published. |
| `site/_headers` | Security headers (Content-Security-Policy, HTTPS-only, anti-framing, etc.). |
| `site/vendor/` | Pinned copy of the Supabase JavaScript library (v2.117.2, MIT). |
| `supabase/` | Database security scripts. Run in the Supabase SQL Editor; **not** published. |
| `netlify.toml` | Tells Netlify to publish `site/` with no build step. |

## Making a change

Edit files in `site/`, commit, and push to `main`. Netlify publishes the new version in about a minute.
Check the deploy under Netlify → Deploys.

## Contact form

The inquiry form uses Netlify Forms (`property-inquiry`). Email notifications go to
aburns@burnspropertiesinc.com (Netlify → Forms → Form notifications). A backup copy of each
inquiry is saved to Supabase for the admin page at `/admin`.

## Keys

The only key in this repository is the Supabase **publishable** key, which is designed to be
public. Never commit a Supabase secret key (`sb_secret_…` / `service_role`) or any other password.
