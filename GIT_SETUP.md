# incoming2.0-server — Git push workflow

Create an empty GitHub repository named `incoming2.0-server`, then from the project directory:

```bash
git init
git branch -M main
git add .
git commit -m "Initial Incoming 2.0 server"
git remote add origin https://github.com/YOUR_USERNAME/incoming2.0-server.git
git push -u origin main
```

For later updates:

```bash
git add .
git commit -m "Describe the server change"
git push origin main
```

Once the repository is connected to Cloudflare Workers Builds, a push to `main` can deploy automatically.

Do not commit real secrets. Runtime secrets belong in Cloudflare Dashboard > Worker > Settings > Variables & Secrets.
