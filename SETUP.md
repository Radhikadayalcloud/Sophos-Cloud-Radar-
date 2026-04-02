# Setup Guide

## Quick Start (5 minutes)

### 1. Clone the repo

```bash
git clone https://github.com/YOUR-USERNAME/sophos-cloud-radar.git
cd sophos-cloud-radar
```

### 2. Install dependencies

```bash
npm install
```

### 3. Start the dev server

```bash
npm run dev
```

Open http://localhost:5173

### 4. Enter your API key

Get a free Anthropic API key at https://console.anthropic.com/keys

Paste it into the API KEY field in the header. It starts with sk-ant-

### 5. Run your first scan

- Click Load Demo
- Click Analyze Config
- Results appear in 2-4 seconds

---

## Deploy to Lovable

Lovable handles hosting and keeps your API key secure on the server.

### Steps

1. Go to https://lovable.dev and create a project
2. Connect a Supabase project to your Lovable project
3. In Supabase dashboard go to Edge Functions
4. Create a new function called analyze-config
5. Add ANTHROPIC_API_KEY as a secret in Supabase
6. Paste SophosCloudRadar.jsx as your main component
7. Update the fetch URL from api.anthropic.com to your Edge Function URL
8. Deploy - Lovable gives you a public URL

### Why Lovable

- API key stored securely as Supabase secret - never in the browser
- Public shareable URL for your team
- No CORS issues
- Free tier available

---

## Deploy to Vercel or Netlify

```bash
npm run build
```

Upload the dist/ folder to Vercel, Netlify or any static host.

Note: You will need to proxy the Anthropic API call through a serverless function to keep the API key secure. Do not expose the API key in the frontend bundle.

---

## Jira Setup

1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Create a new API token
3. In Sophos Cloud Radar click Jira Settings on the results screen
4. Enter your Jira base URL (e.g. yourcompany.atlassian.net - no https://)
5. Enter your project key (e.g. SEC)
6. Enter your Atlassian email and the API token
7. Click Save

Settings are saved to localStorage so you only configure once.

---

## Environment Variables

If self-hosting with a backend proxy, set:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Never commit this to git. Add .env to .gitignore (already included).

---

## Folder Structure

```
sophos-cloud-radar/
├── SophosCloudRadar.jsx    Main React component
├── src/
│   └── main.jsx            Vite entry point
├── index.html              HTML shell
├── package.json            Dependencies
├── vite.config.js          Vite config
├── README.md               Full documentation
├── SETUP.md                This file
├── CHANGELOG.md            Version history
└── .gitignore              Git ignore rules
```

---

## Troubleshooting

### Analysis fails with API error
- Check your API key starts with sk-ant-
- Check you have credits at console.anthropic.com
- Try a shorter config (under 2000 characters)

### PDF export does not open
- Allow popups for the site in your browser
- Try a different browser

### Analysis is slow
- The tool uses Claude Haiku 4.5 which is optimised for speed
- Expected time is 2-4 seconds
- If slower check your internet connection

### Jira ticket creation fails
- Check Jira base URL does not include https://
- Check API token is valid at id.atlassian.com
- Check project key matches exactly (case sensitive)
