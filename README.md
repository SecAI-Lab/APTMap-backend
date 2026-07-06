# APT Map — Backend

> **🏆 Distinguished Paper Award — ACM CCS 2025**

This repository contains the backend for [APT Map](https://lngt-apt-study-map.vercel.app/), an interactive web application for exploring Advanced Persistent Threat (APT) incidents. The application accompanies the following research paper:

**A Decade-long Landscape of Advanced Persistent Threats: Longitudinal Analysis and Global Trends**
DOI: [10.1145/3719027.3765085](https://doi.org/10.1145/3719027.3765085)
*Proceedings of the 32nd ACM SIGSAC Conference on Computer and Communications Security, CCS 2025*

---

## Overview

The APT Map and its corresponding timeline chart are built using the [React](https://react.dev/) framework and the [amCharts](https://www.amcharts.com/) library to enable interactive user experiences. The frontend is integrated with this Flask-based backend, deployed on the [Heroku](https://www.heroku.com/) platform.

The backend is a Flask REST API that serves APT incident data stored in an Excel database and exposes endpoints for data retrieval, LLM-powered report extraction, and community entry submission via GitHub pull requests.

## Features

- **Data API** — Serves the APT incident dataset from `APT MAP Data.xlsx`
- **Report extraction** — Given a URL or PDF, uses Claude, Gemini, or GPT to extract structured APT incident fields
- **Community contributions** — Entry submissions create GitHub pull requests for maintainer review rather than writing directly to the database

## Running Locally

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your environment variables
python backend.py
```

The server starts on `http://localhost:8000`.

## Citation

If you use this dataset or tool in your research, please cite:

```bibtex
@inproceedings{aptmap2025,
  title     = {A Decade-long Landscape of Advanced Persistent Threats: Longitudinal Analysis and Global Trends},
  author = {Yuldoshkhujaev, Shakhzod and Jeon, Mijin and Kim, Doowon and Nikiforakis, Nick and Koo, Hyungjoon},
  booktitle = {Proceedings of the 32nd ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  year      = {2025}
}
```
