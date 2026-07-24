## ⚠️ SECURITY NOTICE — READ BEFORE DEPLOYING

### Rotate any previously committed secrets immediately

If any version of this codebase was previously committed with hardcoded values for any of the following, **rotate those credentials NOW** — they may still be visible in git history:

- `COGNITO_CLIENT_SECRET` — regenerate in AWS Cognito console
- `BREVO_SMTP_PASS` — regenerate in Brevo dashboard
- Any AWS IAM access keys — rotate in IAM console
- Any hardcoded admin email addresses — change or ensure accounts are secured

Git history is permanent. Even after removing a secret from code, it exists in every past commit. Use `git filter-repo` or BFG Repo Cleaner to scrub history if needed.

### Required before deploy

1. Copy `.env.example` to `.env` and fill in all values
2. Ensure `.env` is in `.gitignore` (it is — do not remove it)
3. Set all environment variables in your Vercel project settings
4. Verify `ADMIN_EMAILS` is set to your actual admin email(s) in Vercel env vars

# Rent-Nivas
This Is India Best Platform To List Your House Or Rent A House
