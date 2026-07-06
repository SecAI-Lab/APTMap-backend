from flask import Flask, jsonify, request
import requests
import os
import json
import re
import base64
import uuid
import threading
import schedule
import time
# import subprocess        # unused — run_claude_job disabled
# import shutil            # unused — _find_claude_cli disabled
import io
import pandas as pd
from langchain_google_genai import GoogleGenerativeAI, GoogleGenerativeAIEmbeddings
from langchain.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain_community.vectorstores import FAISS
from dotenv import load_dotenv
from flask_cors import CORS

load_dotenv()


# --- run_claude local CLI feature (disabled) ---
# def _find_claude_cli():
#     candidates = [
#         shutil.which("claude"),
#         os.path.expanduser("~/.local/bin/claude"),
#         "/usr/local/bin/claude",
#         "/usr/bin/claude",
#     ]
#     for path in candidates:
#         if path and os.path.isfile(path) and os.access(path, os.X_OK):
#             return path
#     return None
#
# CLAUDE_CLI = _find_claude_cli()
# --- end run_claude local CLI feature ---

app = Flask(__name__)
CORS(app) 

url = os.getenv("REPOSITORY_API")
token = os.getenv("GITHUB_TOKEN")
GITHUB_REPO = os.getenv("GITHUB_REPO", "SecAI-Lab/APTMap-backend")
gemini_api_key = os.getenv("GOOGLE_API_KEY")
LLM_MODEL = "gemini-1.5-flash-latest"
EMBEDDING_MODEL = 'models/embedding-001'

EXCEL_FILE_PATH = "APT MAP Data.xlsx"
THREAT_COUNTRY_FILE = "Threat Country.xlsx"
ENTRY_COLUMNS = [
    "Date",
    "Download Url",
    "Source",
    "CVE",
    "Zero-Day",
    "Threat Actor",
    "Threat Country",
    "Victims",
    "New Start Date",
    "New End Date",
    "Duration",
    "AttackVector",
    "Malware",
    "Target Sectors",
]
REQUIRED_ENTRY_COLUMNS = {"Date"}
TIMELINE_QUESTION_INDEX = 6
AUTOMATION_QUESTIONS = [
    "Was a zero-day vulnerability used in this attack? Answer with TRUE or FALSE.",
    "What is the name of the threat actor group?",
    "Which country is the threat actor attributed to?",
    "Which countries, organizations, or groups were targeted?",
    "What are the initial attack vectors described in this report?",
    "Which specific malware, tool names, or software frameworks are used in this attack?",
    "Identify the start date, end date, and total duration of the attack timeline.",
    "Identify the targeted sectors in this document.",
]

last_commit_time = None
existing_links = []
new_links_added = []

_JOBS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".claude_jobs")
os.makedirs(_JOBS_DIR, exist_ok=True)


def _job_path(job_id):
    return os.path.join(_JOBS_DIR, f"{job_id}.json")


def _write_job(job_id, state):
    with open(_job_path(job_id), "w") as f:
        json.dump(state, f)


def _read_job(job_id):
    path = _job_path(job_id)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


# --- run_claude threat actor lookup (disabled) ---
# def load_threat_actor_lookup():
#     """Build a dict: normalised_name -> (primary_name, country_code)
#     covering both the Threat Actor column and every alias in Other Names."""
#     lookup = {}
#     try:
#         df = pd.read_excel(THREAT_COUNTRY_FILE)
#         for _, row in df.iterrows():
#             primary = str(row.get("Threat Actor") or "").strip()
#             country = str(row.get("Country") or "").strip()
#             if not primary or primary.lower() == "nan":
#                 continue
#             country = country if country and country.lower() != "nan" else "N/A"
#             lookup[primary.lower()] = (primary, country)
#
#             other = str(row.get("Other Names") or "")
#             if other and other.lower() != "nan":
#                 for alias in other.split(","):
#                     alias = alias.strip()
#                     if alias:
#                         lookup[alias.lower()] = (primary, country)
#     except Exception as e:
#         print(f"Warning: could not load {THREAT_COUNTRY_FILE}: {e}")
#     return lookup
#
# threat_actor_lookup = load_threat_actor_lookup()
# --- end run_claude threat actor lookup ---

excel_lock = threading.Lock()


def read_apt_dataframe():
    if os.path.exists(EXCEL_FILE_PATH):
        df = pd.read_excel(EXCEL_FILE_PATH)
    else:
        df = pd.DataFrame(columns=ENTRY_COLUMNS)

    for column in ENTRY_COLUMNS:
        if column not in df.columns:
            df[column] = ""

    ordered_columns = ENTRY_COLUMNS + [column for column in df.columns if column not in ENTRY_COLUMNS]
    return df[ordered_columns]


def write_apt_dataframe(df):
    df.to_excel(EXCEL_FILE_PATH, index=False)


def normalize_cell(value):
    if pd.isna(value):
        return ""
    if hasattr(value, "strftime"):
        return value.strftime("%Y-%m-%d")
    return value


def dataframe_to_records(df, include_id=False):
    normalized_df = df.apply(lambda column: column.map(normalize_cell))
    records = normalized_df.to_dict(orient="records")
    if include_id:
        for index, record in enumerate(records):
            record["id"] = str(index)
    return records


def get_entry_index(entry_id, df):
    try:
        index = int(entry_id)
    except (TypeError, ValueError):
        return None

    if index < 0 or index >= len(df):
        return None
    return index


def validate_entry_payload(payload, partial=False):
    if not isinstance(payload, dict):
        return None, "Request body must be a JSON object."

    allowed_columns = set(ENTRY_COLUMNS)
    unknown_columns = [column for column in payload.keys() if column not in allowed_columns]
    if unknown_columns:
        return None, f"Unknown columns: {', '.join(unknown_columns)}"

    cleaned = {}
    for column in ENTRY_COLUMNS:
        if column in payload:
            value = payload[column]
            if column in REQUIRED_ENTRY_COLUMNS:
                cleaned[column] = "" if value is None else str(value).strip()
            else:
                cleaned[column] = "N/A" if value is None or str(value).strip() == "" else value
        elif not partial:
            cleaned[column] = "N/A" if column not in REQUIRED_ENTRY_COLUMNS else ""

    date_value = cleaned.get("Date")
    if not partial or date_value:
        if not date_value:
            return None, "Date is required."
        parsed_date = pd.to_datetime(date_value, errors="coerce")
        if pd.isna(parsed_date):
            return None, "Date must be a valid date."
        cleaned["Date"] = parsed_date.strftime("%Y-%m-%d")

    return cleaned, None


def validate_delete_admin(payload):
    expected_token = os.getenv("DELETE_ADMIN_TOKEN") or os.getenv("ADMIN_API_KEY")
    if not expected_token:
        return jsonify({"error": "Delete admin token is not configured on the backend."}), 403

    provided_token = payload.get("adminToken") or request.headers.get("X-Delete-Admin-Token", "")
    if provided_token != expected_token:
        return jsonify({"error": "A valid admin token is required to delete entries."}), 401

    return None


def load_general_prompt():
    prompt = """You are an experienced security engineer analyzing the security articles describing cases of APT attacks. \n    You need to answer the questions in the scope of the provided file as precise, accurate and short as possible.\n    For each question just give me the answers straight without additional explanation of it. \n    If the information is not mentioned answer with \"Not mentioned\". \n    Given below are the contents of the file and question of the user.\n    context = {context}\n    question = {question}\n    """
    return ChatPromptTemplate.from_template(prompt)

def load_timeline_prompt():
    prompt = """
    You are an experienced security engineer analyzing attack timelines. Use the provided timestamps to determine:
    - The start date of the attack
    - The end date of the attack
    - The total duration of the attack in days.

    Some timestamps may be relative (e.g., "two weeks ago"). Please interpret these based on the release date of the information by assuming that release data is today.
    In case if either one or all of dates are empty, answer with "No information".
    Timestamps: {timestamps}
    Release Date: {releaseDate}

    Respond only with:
    - Start Date: [start_date]
    - End Date: [end_date]
    - Total Duration: [duration_in_days]
    """
    return ChatPromptTemplate.from_template(prompt)

def llm_response_text(response):
    return response.content if hasattr(response, "content") else str(response)

def parse_timeline_response(response_text):
    text = llm_response_text(response_text)

    def extract_value(label):
        match = re.search(rf"{label}:\s*(.+)", text, re.IGNORECASE)
        return match.group(1).strip() if match else "Not specified"

    return {
        "start_date": extract_value("Start Date"),
        "end_date": extract_value("End Date"),
        "duration": extract_value("Total Duration"),
    }

def load_llm():
    return GoogleGenerativeAI(
        model=LLM_MODEL,
        api_key=gemini_api_key
    )

def load_knowledge_base(article):
    embeddings = GoogleGenerativeAIEmbeddings(model=EMBEDDING_MODEL, api_key=gemini_api_key)
    db_path = f'vectorstoreWithImagesGoogleEmb/db_faiss_{article}'
    return FAISS.load_local(db_path, embeddings, allow_dangerous_deserialization=True)

def extract_links(content):
    pattern = re.compile(r'\* ([A-Za-z]+\s\d{1,2}) - \[.*?\]\((https?://[^\s)]+)\)')
    matches = pattern.findall(content)

    year_pattern = re.compile(r'## (\d{4})')
    current_year = None
    year_match = year_pattern.search(content)
    if year_match:
        current_year = year_match.group(1)

    links = []
    for month_day, url in matches:
        if current_year:
            formatted_date = f"{current_year}-{month_day.replace(' ', '-')}"
            links.append((formatted_date, url))
    return links


def extract_cve_using_ioc_parser(text):
    try:
        url = "https://api.iocparser.com/raw"
        headers = {'Content-Type': 'text/plain'}
        response = requests.post(url, headers=headers, data=text)
        if response.status_code == 200:
            data = response.json().get('data', {})
            return data.get('CVE', [])
        else:
            print(f"Failed to retrieve CVE data: {response.status_code}")
            return []
    except Exception as e:
        print(f"Error extracting CVE using IOC Parser: {e}")
        return []

def check_readme_update():
    global last_commit_time, existing_links

    headers = {"Authorization": f"token {token}"}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Failed to retrieve data: {response.status_code}")
        return

    data = response.json()
    new_commit_time = data['sha']
    new_content = base64.b64decode(data['content']).decode('utf-8')

    if last_commit_time is None:
        last_commit_time = new_commit_time
        existing_links = extract_links(new_content)
        print("Initial links loaded.")
        return

    if last_commit_time == new_commit_time:
        print("No update detected.")
        return

    print(f"Update detected. New commit SHA: {new_commit_time}")
    new_links = extract_links(new_content)
    added_links = [link for link in new_links if link not in existing_links]

    if added_links:
        print(f"New links found: {added_links}")
        process_links(added_links)
        existing_links = new_links
    else:
        print("No new links to process.")

    last_commit_time = new_commit_time

def process_links(links):
    llm = load_llm()
    general_prompt = load_general_prompt()
    timeline_prompt = load_timeline_prompt()

    df = read_apt_dataframe()
    existing_urls = set(df['Download Url'].dropna()) if not df.empty else set()

    for link in links:
        link_date, link_url = link

        if link_url in existing_urls:
            print(f"Skipping duplicate URL: {link_url}")
            continue

        try:
            response = requests.get(link_url)
            if response.status_code == 200:
                text = response.text
                cve_data = extract_cve_using_ioc_parser(text)
                cve_list = ', '.join(cve_data)
            else:
                cve_list = "Error retrieving document"

            answers = []
            start_date, end_date, duration = "Not specified", "Not specified", "Not specified"
            for idx, question in enumerate(AUTOMATION_QUESTIONS):
                try:
                    if idx == TIMELINE_QUESTION_INDEX:
                        raw_response = llm.invoke(
                            timeline_prompt.format_prompt(timestamps=text, releaseDate=link_date)
                        )
                        response = llm_response_text(raw_response)
                        timeline = parse_timeline_response(response)
                        start_date = timeline["start_date"]
                        end_date = timeline["end_date"]
                        duration = timeline["duration"]
                    else:
                        raw_response = llm.invoke(
                            general_prompt.format_prompt(context=text, question=question)
                        )
                        response = llm_response_text(raw_response)
                    answers.append(response)
                except Exception as e:
                    print(f"Error processing question '{question}': {e}")
                    answers.append("Error")

            df = pd.concat(
                [df, pd.DataFrame({
                    "Date": [link_date],
                    "Download Url": [link_url],
                    "CVE": [cve_list],
                    "Zero-Day": [answers[0]],
                    "Threat Actor": [answers[1]],
                    "Threat Country": [answers[2]],
                    "Victims": [answers[3]],
                    "AttackVector": [answers[4]],
                    "Malware": [answers[5]],
                    "Timeline": [answers[6]],
                    "Duration": [duration],
                    "New Start Date": [start_date],
                    "New End Date": [end_date],
                    "Target Sectors": [answers[7]]
                })],
                ignore_index=True
            )
            existing_urls.add(link_url)

        except Exception as e:
            print(f"Failed to process link {link_url}: {e}")

    with excel_lock:
        write_apt_dataframe(df)

def run_scheduler():
    schedule.every().monday.at("00:00").do(check_readme_update)
    while True:
        schedule.run_pending()
        time.sleep(1)

if not hasattr(run_scheduler, "initialized"):
    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    run_scheduler.initialized = True

def create_entry_pr(entry):
    base_owner, base_repo_name = GITHUB_REPO.split("/", 1)
    file_path = "APT MAP Data.xlsx"
    gh_api = "https://api.github.com"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }

    encoded_path = file_path.replace(" ", "%20")

    file_resp = requests.get(
        f"{gh_api}/repos/{base_owner}/{base_repo_name}/contents/{encoded_path}",
        headers=headers,
    )
    if file_resp.status_code != 200:
        return None, f"Failed to fetch Excel from GitHub: {file_resp.json().get('message', '')}"

    file_data = file_resp.json()
    file_sha = file_data["sha"]
    file_content = base64.b64decode(file_data["content"])

    df = pd.read_excel(io.BytesIO(file_content))
    for col in ENTRY_COLUMNS:
        if col not in df.columns:
            df[col] = ""
    df = pd.concat([df, pd.DataFrame([entry], columns=ENTRY_COLUMNS)], ignore_index=True)

    output = io.BytesIO()
    df.to_excel(output, index=False)
    new_content_b64 = base64.b64encode(output.getvalue()).decode()

    ref_resp = requests.get(
        f"{gh_api}/repos/{base_owner}/{base_repo_name}/git/ref/heads/main",
        headers=headers,
    )
    if ref_resp.status_code != 200:
        return None, f"Failed to get main branch: {ref_resp.json().get('message', '')}"
    main_sha = ref_resp.json()["object"]["sha"]

    branch_name = f"add-entry-{uuid.uuid4().hex[:8]}"
    branch_resp = requests.post(
        f"{gh_api}/repos/{base_owner}/{base_repo_name}/git/refs",
        headers=headers,
        json={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
    )
    if branch_resp.status_code != 201:
        return None, f"Failed to create branch: {branch_resp.json().get('message', '')}"

    commit_resp = requests.put(
        f"{gh_api}/repos/{base_owner}/{base_repo_name}/contents/{encoded_path}",
        headers=headers,
        json={
            "message": f"Add APT entry: {entry.get('Threat Actor', 'Unknown')} ({entry.get('Date', '')})",
            "content": new_content_b64,
            "sha": file_sha,
            "branch": branch_name,
        },
    )
    if commit_resp.status_code not in (200, 201):
        return None, f"Failed to commit file: {commit_resp.json().get('message', '')}"

    field_labels = [
        ("Date", "Date"),
        ("Download Url", "Download Url"),
        ("Source", "Source"),
        ("CVE", "CVE"),
        ("Zero-Day", "Zero-Day"),
        ("Threat Actor", "Threat Actor"),
        ("Threat Country", "Threat Country"),
        ("Victims", "Victims"),
        ("New Start Date", "New Start Date"),
        ("New End Date", "New End Date"),
        ("Duration", "Duration"),
        ("AttackVector", "AttackVector"),
        ("Malware", "Malware"),
        ("Target Sectors", "Target Sectors"),
    ]
    table_rows = "\n".join(
        f"| {label} | {entry.get(col, '')} |"
        for col, label in field_labels
    )
    pr_body = (
        "## New APT Entry Submission\n\n"
        "| Field | Value |\n"
        "|-------|-------|\n"
        f"{table_rows}"
    )

    pr_resp = requests.post(
        f"{gh_api}/repos/{base_owner}/{base_repo_name}/pulls",
        headers=headers,
        json={
            "title": f"Add APT entry: {entry.get('Threat Actor', 'Unknown')} ({entry.get('Date', '')})",
            "head": branch_name,
            "base": "main",
            "body": pr_body,
        },
    )
    if pr_resp.status_code != 201:
        return None, f"Failed to create PR: {pr_resp.json().get('message', '')}"

    return pr_resp.json()["html_url"], None


@app.route('/')
def home():
    return "Welcome to the README update checker!"

@app.route('/get-data', methods=['GET'])
def get_data():
    return jsonify({"message": f"Excel file available at {EXCEL_FILE_PATH}"})

@app.route('/get-apt-data', methods=['GET', 'POST', 'PUT', 'DELETE'])
def get_apt_data():
    try:
        if request.method == 'GET':
            with excel_lock:
                df = read_apt_dataframe()

            df = df.fillna('N/A')

            if 'Zero-Day' in df.columns:
                df['Zero-Day'] = df['Zero-Day'].apply(
                    lambda x: True if x == 1 else (False if x == 0 else x)
                )

            data = dataframe_to_records(df)
            return jsonify(data), 200

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "Request body must be a JSON object."}), 400

        if request.method == 'POST':
            entry_payload = dict(payload.get("entry", payload))
            entry_payload.pop("githubToken", None)
            entry, error = validate_entry_payload(entry_payload)
            if error:
                return jsonify({"error": error}), 400

            pr_url, pr_error = create_entry_pr(entry)
            if pr_error:
                return jsonify({"error": pr_error}), 500

            return jsonify({
                "message": f"Pull request created — awaiting review.",
                "pr_url": pr_url,
                **entry,
            }), 201

        entry_id = payload.get("id")

        if request.method == 'PUT':
            entry_payload = payload.get("entry", {key: value for key, value in payload.items() if key != "id"})
            entry, error = validate_entry_payload(entry_payload, partial=True)
            if error:
                return jsonify({"error": error}), 400

            with excel_lock:
                df = read_apt_dataframe()
                index = get_entry_index(entry_id, df)
                if index is None:
                    return jsonify({"error": "Entry not found."}), 404

                for column, value in entry.items():
                    df.at[index, column] = value

                write_apt_dataframe(df)
                updated_entry = dataframe_to_records(df.iloc[[index]], include_id=True)[0]
                updated_entry["id"] = str(index)

            return jsonify(updated_entry), 200

        if request.method == 'DELETE':
            admin_error = validate_delete_admin(payload)
            if admin_error is not None:
                return admin_error

            with excel_lock:
                df = read_apt_dataframe()
                index = get_entry_index(entry_id, df)
                if index is None:
                    return jsonify({"error": "Entry not found."}), 404

                df = df.drop(index=index).reset_index(drop=True)
                write_apt_dataframe(df)

            return jsonify({"message": "Entry deleted."}), 200

        return jsonify({"error": "Method not allowed."}), 405
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =============================================================================
# RUN CLAUDE LOCAL CLI FEATURE (disabled — kept for reference)
# To re-enable: uncomment this block and restore the imports/variables above.
# =============================================================================
# def _clean_value(val, fallback="N/A"):
#     s = str(val).strip() if val is not None else ""
#     return fallback if s.lower() in ("", "none", "null") else s
#
#
# def run_claude_job(job_id):
#     try:
#         with excel_lock:
#             df = read_apt_dataframe()
#         existing_urls = set(df["Download Url"].dropna().astype(str))
#         latest_date = "2025-01-01"
#         if not df.empty:
#             dates = pd.to_datetime(df["Date"], errors="coerce").dropna()
#             if not dates.empty:
#                 latest_date = dates.max().strftime("%Y-%m-%d")
#         existing_urls_list = "\n".join(f"- {u}" for u in sorted(existing_urls)) if existing_urls else "  (none yet)"
#         search_prompt = f"""...(web search prompt)..."""
#         if not CLAUDE_CLI:
#             _write_job(job_id, {"status": "error", "error": "Claude Code CLI not found."})
#             return
#         result = subprocess.run(
#             [CLAUDE_CLI, "-p", search_prompt, "--allowedTools", "WebSearch,WebFetch"],
#             capture_output=True, text=True, timeout=300,
#         )
#         # ... parse response, dedup, write to Excel ...
#         _write_job(job_id, {"status": "done", "added": ..., "skipped": ..., "entries": ...})
#     except subprocess.TimeoutExpired:
#         _write_job(job_id, {"status": "error", "error": "Claude Code timed out after 5 minutes."})
#     except Exception as e:
#         _write_job(job_id, {"status": "error", "error": str(e)})
#
#
# @app.route('/run-claude', methods=['POST'])
# def run_claude_start():
#     job_id = str(uuid.uuid4())
#     _write_job(job_id, {"status": "running"})
#     thread = threading.Thread(target=run_claude_job, args=(job_id,))
#     thread.daemon = True
#     thread.start()
#     return jsonify({"jobId": job_id}), 202
#
#
# @app.route('/run-claude/<job_id>', methods=['GET'])
# def run_claude_status(job_id):
#     job = _read_job(job_id)
#     if job is None:
#         return jsonify({"error": "Job not found."}), 404
#     return jsonify(job), 200
# =============================================================================
# END RUN CLAUDE LOCAL CLI FEATURE
# =============================================================================

# ---------------------------------------------------------------------------
# Single-report extraction  (POST /extract-report, GET /extract-report/<id>)
# ---------------------------------------------------------------------------

def _extract_pdf_text(pdf_bytes):
    import pypdf
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    text = " ".join(page.extract_text() or "" for page in reader.pages)
    return re.sub(r'\s+', ' ', text).strip()[:60000]


def _fetch_report_text(url):
    from bs4 import BeautifulSoup
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    resp = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
    resp.raise_for_status()
    content_type = resp.headers.get("Content-Type", "")
    if "application/pdf" in content_type or url.lower().split("?")[0].endswith(".pdf"):
        return _extract_pdf_text(resp.content)
    soup = BeautifulSoup(resp.content, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = soup.get_text(" ", strip=True)
    return re.sub(r'\s+', ' ', text).strip()[:60000]


def _build_extraction_prompt(report_text, url=""):
    intro = f"Analyze the following technical report URL: {url}" if url else "Analyze the following technical report content:"
    url_field = url if url else "full URL of the report"
    return f"""{intro}

Use only information explicitly stated in the technical report itself. Do not use external sources, prior knowledge, threat intelligence databases, vendor blogs, news articles, search results, or assumptions.

First, determine whether the report describes exactly one APT incident.
If the report contains multiple APT campaigns, multiple APT incidents, multiple unrelated threat actors, multiple unrelated operations, or functions as a quarterly/monthly roundup, threat landscape summary, campaign collection, or news digest, return exactly this text and nothing else:
    "The technical report contains multiple APT incidents"
Do not extract individual sub-campaigns from a multi-campaign report. Do not split a roundup report into separate JSON objects.
If the report describes exactly one APT incident, extract the structured information using this exact schema. Do not add, remove, or rename fields.
[
  {{
    "Date": "publication date in YYYY-MM-DD format",
    "Download Url": "{url_field}",
    "Source": "the technical report publisher (e.g., CheckPoint, Palo Alto Networks)",
    "CVE": "comma-separated CVE IDs mentioned in the report, or N/A",
    "Zero-Day": "TRUE if a zero-day was exploited, FALSE if not, N/A if not mentioned",
    "Threat Actor": "name of the APT group or threat actor, or N/A",
    "Threat Country": "country attributed to the threat actor in ISO 3166-1 alpha-2 format, e.g., US, RU, CN, or N/A",
    "Victims": "comma-separated victim countries in ISO 3166-1 alpha-2 format, e.g., US, RU, CN, or N/A",
    "New Start Date": "earliest known discovery date of related activity in YYYY-MM-DD format, or empty string if unknown.",
    "New End Date": "latest known discovery date of related activity in YYYY-MM-DD format, or empty string if unknown.",
    "Duration": "total duration of the campaign in days as a number, or N/A if unknown",
    "AttackVector": "initial attack vectors, or N/A. Use: Spear Phishing, Phishing, Watering Hole, Credential Reuse, Social Engineering, Exploit Vulnerability, Malicious Documents, Covert Channels, Drive-by Download, Removable Media, Website Equipping, Meta Data Monitoring.",
    "Malware": "specific malware or tool names used in the attack, or N/A",
    "Target Sectors": "targeted sectors, or N/A. Use: Government and Defense Agencies, Corporations and Businesses, Financial Institutions, Healthcare, Energy and Utilities, Cloud/IoT Services, Manufacturing, Education and Research Institutions, Media and Entertainment Companies, Critical Infrastructure, Non-Governmental Organizations (NGOs) and Nonprofits, Individuals."
  }}
]
Final output:
 - If the report describes exactly one APT incident, return only the JSON array in the exact schema above.
 - Do not include markdown fences, explanations, citations, comments, or reasoning.

Report content:
{report_text}"""


def _complete_llm(llm, api_key, prompt):
    if llm == "claude":
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model="claude-opus-4-8",
            max_tokens=8000,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    if llm == "gemini":
        import google.genai as genai
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(model="gemini-2.5-flash", contents=prompt)
        return resp.text

    if llm == "chatgpt":
        import openai
        client = openai.OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=8000,
        )
        return resp.choices[0].message.content

    raise ValueError(f"Unknown llm: {llm}")


def extract_report_job(job_id, llm, api_key, source_type, url, pdf_bytes):
    try:
        if source_type == "pdf":
            report_text = _extract_pdf_text(pdf_bytes)
        else:
            report_text = _fetch_report_text(url)

        if not report_text.strip():
            _write_job(job_id, {"status": "error", "error": "Could not extract text from the report."})
            return

        prompt = _build_extraction_prompt(report_text, url if source_type == "url" else "")
        response_text = _complete_llm(llm, api_key, prompt)

        if "The technical report contains multiple APT incidents" in response_text:
            _write_job(job_id, {"status": "error", "error": "The technical report contains multiple APT incidents. Please provide a report covering exactly one incident."})
            return

        json_str = response_text.strip()
        json_str = re.sub(r"^```(?:json)?\n?", "", json_str)
        json_str = re.sub(r"\n?```$", "", json_str).strip()

        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError:
            _write_job(job_id, {"status": "error", "error": f"Could not parse model response as JSON. Preview: {response_text[:300]}"})
            return

        entry = parsed[0] if isinstance(parsed, list) else parsed

        if source_type == "url" and not entry.get("Download Url") or entry.get("Download Url") in ("", "N/A", "full URL of the report"):
            entry["Download Url"] = url

        _write_job(job_id, {"status": "done", "entry": entry})

    except Exception as e:
        _write_job(job_id, {"status": "error", "error": str(e)})


@app.route('/extract-report', methods=['POST'])
def extract_report_start():
    try:
        payload = request.get_json(force=True) or {}
        llm = payload.get("llm", "")
        api_key = (payload.get("apiKey") or "").strip()
        source_type = payload.get("sourceType", "url")

        if llm not in ("claude", "gemini", "chatgpt"):
            return jsonify({"error": "llm must be claude, gemini, or chatgpt"}), 400
        if not api_key:
            return jsonify({"error": "apiKey is required"}), 400

        url = ""
        pdf_bytes = None

        if source_type == "url":
            url = (payload.get("url") or "").strip()
            if not url.startswith(("http://", "https://")):
                return jsonify({"error": "A valid URL starting with http:// or https:// is required"}), 400
        elif source_type == "pdf":
            pdf_b64 = payload.get("pdfBase64", "")
            if not pdf_b64:
                return jsonify({"error": "pdfBase64 is required for PDF source"}), 400
            pdf_bytes = base64.b64decode(pdf_b64)
            if len(pdf_bytes) > 15 * 1024 * 1024:
                return jsonify({"error": "PDF must be under 15 MB"}), 400
        else:
            return jsonify({"error": "sourceType must be url or pdf"}), 400

        job_id = str(uuid.uuid4())
        _write_job(job_id, {"status": "running"})
        thread = threading.Thread(target=extract_report_job, args=(job_id, llm, api_key, source_type, url, pdf_bytes))
        thread.daemon = True
        thread.start()

        return jsonify({"jobId": job_id}), 202

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/extract-report/<job_id>', methods=['GET'])
def extract_report_status(job_id):
    job = _read_job(job_id)
    if job is None:
        return jsonify({"error": "Job not found."}), 404
    return jsonify(job), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True, use_reloader=True)

