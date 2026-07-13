# QA Signal

Paste deploy, build, CI, or runtime logs for structured analysis with Jira-ready bug reports. Browse competitor quality trends and Cloudways guides in the QA Knowledge Hub.

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:3000`

## Deploy on Cloudways (Node.js)

In **Application Settings → Deployment**:

| Setting | Value |
|---------|--------|
| **Application type** | Node.js |
| **Node.js version** | 18 or 20 |
| **Document root** | `public` (optional — API serves the UI from Express) |
| **Entry point** | `src/server.js` |
| **Build command** | `npm install --production` |
| **Start command** | `npm start` |

Cloudways sets `PORT` automatically — the app listens on `process.env.PORT`.

### Deploy via Git (typical flow)

1. Push this repo to your Git remote (GitHub/GitLab/Bitbucket).
2. In Cloudways → **Deployment via Git** → connect the repo and branch.
3. Set build/start commands above and deploy.
4. Open your Cloudways app URL.

### Manual deploy (SFTP)

```bash
npm install --production
npm start
```

### Health check

```bash
curl https://your-app.cloudwaysapps.com/api/health
```

## API

| Method | Path | Body | Purpose |
|--------|------|------|---------|
| GET | `/api/health` | — | Runtime check |
| POST | `/api/analyze` | `{ "log": "…" }` | Analyze a log |
| GET | `/api/digest` | — | QA Knowledge Hub feed (optional `?refresh=1`) |

## What it detects

- Pass/fail verdict and exit code
- Exact issues with line numbers and categories
- Copy-paste Jira bug report
- Build phases / timeline
- npm vulnerabilities, deprecations, commands run
- Ansible, Cloudways, Docker, CI log patterns
