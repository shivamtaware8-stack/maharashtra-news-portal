# Demo accounts (local only, never committed)

`demo-users.json` holds DEMO accounts for local testing only.
It stores bcrypt password hashes (never plaintext).
It is git-ignored via `.gitignore`, so test accounts never reach GitHub/Vercel.
The real MongoDB Atlas database is untouched; old Atlas accounts do NOT work here.
