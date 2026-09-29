# OMEGA Deployment Guide

## Frontend → Vercel | Backend → Render

---

## Part 1: Deploy Backend to Render

### Step 1: Create GitHub Repository
Push this entire repo to GitHub first:
```bash
git remote add origin https://github.com/YOUR_USERNAME/omega-ipsec.git
git push -u origin master
```

### Step 2: Create Render Account
1. Go to [render.com](https://render.com) → Sign up with GitHub

### Step 3: New Web Service
1. Click **New** → **Web Service**
2. Connect your GitHub repo: `omega-ipsec`
3. Configure:
   - **Name**: `omega-backend`
   - **Region**: Singapore (closest to India)
   - **Branch**: `master`
   - **Root Directory**: `backend`
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: Free

### Step 4: Add Environment Variables in Render
In your service → **Environment** tab, add:
```
AIR_GAPPED = false
CORS_ORIGINS = ["https://omega-ipsec.vercel.app"]
```
> Replace `omega-ipsec.vercel.app` with your actual Vercel URL after deploying frontend.

### Step 5: Deploy
Click **Create Web Service**. Wait ~3 minutes for build.

Your backend URL will be: `https://omega-backend.onrender.com`

Test it: `https://omega-backend.onrender.com/health`
Expected: `{"status":"HEALTHY","service":"OMEGA",...}`

---

## Part 2: Deploy Frontend to Vercel

### Step 1: Create Vercel Account
1. Go to [vercel.com](https://vercel.com) → Sign up with GitHub

### Step 2: Import Project
1. Click **Add New → Project**
2. Import your `omega-ipsec` GitHub repository
3. Configure:
   - **Framework Preset**: Vite
   - **Root Directory**: `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
   - **Install Command**: `npm install`

### Step 3: Add Environment Variables in Vercel
In **Settings → Environment Variables**, add:
```
VITE_API_BASE_URL = https://omega-backend.onrender.com
```
> Use your actual Render backend URL here.

### Step 4: Deploy
Click **Deploy**. Vercel builds and deploys in ~1-2 minutes.

Your frontend URL will be: `https://omega-ipsec.vercel.app`

---

## Part 3: Post-Deployment — Update CORS

After getting your Vercel URL:
1. Go to Render Dashboard → omega-backend → **Environment**
2. Update `CORS_ORIGINS` to your actual Vercel URL:
   ```
   ["https://omega-ipsec.vercel.app"]
   ```
3. Render auto-redeploys on env var changes.

---

## Local Development (No Cloud)

```powershell
# Terminal 1 — Backend
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2 — Frontend
cd frontend
npm run dev
```

- Backend API: http://127.0.0.1:8000/docs
- Frontend: http://localhost:5173

The Vite dev server proxies `/api` → `http://localhost:8000` automatically.
No `VITE_API_BASE_URL` needed in local mode.

---

## Notes on Free Tier Limitations

**Render Free Tier:**
- Service sleeps after 15 min of inactivity
- Cold start takes ~30-60 seconds on first request
- 512 MB RAM — sufficient for SQLite + analysis of small PCAPs

**Vercel Free Tier:**
- 100 GB bandwidth/month
- Unlimited deployments
- No cold start (static hosting)

---

## Upgrade Path (Production)

- Backend: Render Starter ($7/month) — always-on, no cold start
- Database: Replace SQLite with PostgreSQL (Render managed DB, $7/month)
  - Change `DATABASE_URL` in env to `postgresql://...`
  - SQLAlchemy code is already PostgreSQL-compatible
