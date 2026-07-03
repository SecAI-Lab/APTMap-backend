# APT Map — Backend

> **Distinguished Paper Award — ACM CCS 2025**

This repository contains the backend for [APT Map](https://lngt-apt-study-map.vercel.app/), an interactive web application for exploring Advanced Persistent Threat (APT) incidents. The application accompanies the following research paper:

**APT Map: A Longitudinal Study of Advanced Persistent Threats**
DOI: [10.1145/3719027.3765085](https://doi.org/10.1145/3719027.3765085)
*Proceedings of the ACM Conference on Computer and Communications Security (CCS), 2025*

---

## Overview

The backend is a Flask REST API deployed on Heroku. It serves APT incident data stored in an Excel database and exposes endpoints for data retrieval, LLM-powered report extraction, and community entry submission via GitHub pull requests.

## Features

- **Data API** — Serves the APT incident dataset from `APT MAP Data.xlsx`
- **Report extraction** — Given a URL or PDF, uses Claude, Gemini, or GPT to extract structured APT incident fields
- **Community contributions** — Entry submissions create GitHub pull requests for maintainer review rather than writing directly to the database
- **Threat country lookup** — Country metadata served from `Threat Country.xlsx`

## Tech Stack

- Python / Flask
- Pandas + OpenPyXL (Excel database)
- Anthropic, Google Generative AI, OpenAI (LLM extraction)
- PyGithub (pull request workflow)
- Gunicorn (production server on Heroku)

## Environment Variables

| Variable | Description |
|---|---|
| `GITHUB_TOKEN` | Classic GitHub PAT with `public_repo` scope, used to open pull requests for submitted entries |
| `GITHUB_REPO` | Target repository for pull requests (default: `xininny/APT-backend`) |
| `GOOGLE_API_KEY` | Google AI API key for the embedding/search features |
| `REPOSITORY_API` | GitHub API URL for the data repository |

## Running Locally

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your environment variables
python backend.py
```

The server starts on `http://localhost:8000`.

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/get-apt-data` | Returns all APT entries as JSON |
| `POST` | `/get-apt-data` | Submits a new entry; creates a GitHub pull request |
| `POST` | `/extract-report` | Starts an async LLM extraction job for a URL or PDF |
| `GET` | `/extract-report/<job_id>` | Polls the status of an extraction job |
| `GET` | `/get-threat-country` | Returns country metadata |

## Citation

If you use this dataset or tool in your research, please cite:

```bibtex
@inproceedings{aptmap2025,
  title     = {APT Map: A Longitudinal Study of Advanced Persistent Threats},
  booktitle = {Proceedings of the ACM Conference on Computer and Communications Security (CCS)},
  year      = {2025},
  doi       = {10.1145/3719027.3765085},
  note      = {Distinguished Paper Award}
}
```
