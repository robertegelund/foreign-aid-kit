# Foreign Aid Kit - African Overview with Mapbox and Highcharts

* The Foreign Aid Kit project is made with the goal of making foreign aid transfers more transparent.
* In this early prototype the user can navigate in a Mapbox map. By clicking on each African country, foreign aid information will appear in a Highcharts graph section.

## Setup

1. `npm install`
2. Copy `.env.example` to `.env` and fill in your real `MAPBOX_API_KEY` from your [Mapbox](https://account.mapbox.com/) account
3. `npm run dev` to start the dev server, or `npm run build` to build to `dist/`

The map style/theme (`MAPBOX_STYLE`) is not a secret — it's a plain constant in [src/constants.js](src/constants.js). Change it there if you want a different Mapbox style.

`.env` is gitignored and read at build time via `webpack.DefinePlugin` — no secrets are committed to the repo.

## Deployment (GitHub Pages)

The site is deployed automatically by [.github/workflows/deploy.yml](.github/workflows/deploy.yml) on every push to `master`: it builds the project, copies `data/` and `images/` alongside the bundle, and publishes `dist/` to GitHub Pages. No build output is committed to the repo.

One-time setup in the GitHub repo settings:

1. **Settings → Secrets and variables → Actions** — add a repository secret `MAPBOX_API_KEY` matching `.env.example`.
2. **Settings → Pages → Source** — set to **GitHub Actions** (it currently serves the committed `index.html`/`bundle*.js` at the repo root — switching this is what makes the workflow take over).

Once both are done, the old root-level `index.html`, `bundle*.js` and `bundle*.js.map` are no longer used and can be deleted.