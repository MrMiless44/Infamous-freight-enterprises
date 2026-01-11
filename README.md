# Deploy Site

A minimal static site scaffold with simple deployment options.

## Quick Start

```bash
# Serve locally (Python)
cd /home/vscode/deploy-site
python3 -m http.server 8080
# Open http://localhost:8080
```

## Deploy Options

### GitHub Pages (recommended)

1. Push this folder to a GitHub repository.
2. Add the workflow at `.github/workflows/pages.yml` (already included).
3. Ensure Pages is enabled in repository settings (Source: GitHub Actions).
4. On push to `main`, the site deploys automatically.

### Manual GitHub Pages (local script)

Use `deploy.sh` to publish the current contents to the `gh-pages` branch. Requires a git repo with an `origin` remote.

```bash
cd /home/vscode/deploy-site
bash deploy.sh
```

### Other hosts

- Netlify/Vercel: Import repo and select root as site path.
- AWS S3: Upload the files in this folder to your bucket with static web hosting.
- Any static server: Copy the folder contents to your web root.

## Customize

- Edit `index.html` for content.
- Edit `assets/style.css` for styles.
- Edit `assets/script.js` for behavior.

## Notes

- No build step; it's plain HTML/CSS/JS.
- Keep binaries out of the repo; `.gitignore` includes common ignores.
