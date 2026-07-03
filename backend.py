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
import subprocess
import shutil
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


def _find_claude_cli():
    candidates = [
        shutil.which("claude"),
        os.path.expanduser("~/.local/bin/claude"),
        "/usr/local/bin/claude",
        "/usr/bin/claude",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None

CLAUDE_CLI = _find_claude_cli()

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


def load_threat_actor_lookup():
    """Build a dict: normalised_name -> (primary_name, country_code)
    covering both the Threat Actor column and every alias in Other Names."""
    lookup = {}
    try:
        df = pd.read_excel(THREAT_COUNTRY_FILE)
        for _, row in df.iterrows():
            primary = str(row.get("Threat Actor") or "").strip()
            country = str(row.get("Country") or "").strip()
            if not primary or primary.lower() == "nan":
                continue
            country = country if country and country.lower() != "nan" else "N/A"
            lookup[primary.lower()] = (primary, country)

            other = str(row.get("Other Names") or "")
            if other and other.lower() != "nan":
                for alias in other.split(","):
                    alias = alias.strip()
                    if alias:
                        lookup[alias.lower()] = (primary, country)
    except Exception as e:
        print(f"Warning: could not load {THREAT_COUNTRY_FILE}: {e}")
    return lookup


threat_actor_lookup = load_threat_actor_lookup()

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
    # 링크와 날짜 추출을 위한 패턴
    pattern = re.compile(r'\* ([A-Za-z]+\s\d{1,2}) - \[.*?\]\((https?://[^\s)]+)\)')
    matches = pattern.findall(content)  # 전체 텍스트에서 일괄 추출

    # 연도 초기화
    year_pattern = re.compile(r'## (\d{4})')
    current_year = None

    # 첫 번째 연도 찾기
    year_match = year_pattern.search(content)
    if year_match:
        current_year = year_match.group(1)

    links = []  # 링크 저장용 리스트

    # 링크 추가
    for month_day, url in matches:
        if current_year:  # 연도가 있는 경우 날짜 조합
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
        # 언패킹 오류 수정
        link_date, link_url = link

        if link_url in existing_urls:
            print(f"Skipping duplicate URL: {link_url}")
            continue

        try:
            # 데이터 처리
            response = requests.get(link_url)
            if response.status_code == 200:
                text = response.text
                cve_data = extract_cve_using_ioc_parser(text)
                cve_list = ', '.join(cve_data)
            else:
                cve_list = "Error retrieving document"

            # 질문 응답 처리
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

            # 결과 저장
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

def _clean_value(val, fallback="N/A"):
    s = str(val).strip() if val is not None else ""
    return fallback if s.lower() in ("", "none", "null") else s


def run_claude_job(job_id):
    try:
        with excel_lock:
            df = read_apt_dataframe()

        existing_urls = set(df["Download Url"].dropna().astype(str))

        latest_date = "2025-01-01"
        existing_actors_dates = set()
        if not df.empty:
            dates = pd.to_datetime(df["Date"], errors="coerce").dropna()
            if not dates.empty:
                latest_date = dates.max().strftime("%Y-%m-%d")
            for _, row in df.iterrows():
                actor = str(row.get("Threat Actor", "") or "").strip().lower()
                date = str(row.get("Date", "") or "").strip()
                if actor and actor not in ("n/a", "not mentioned") and date:
                    existing_actors_dates.add((actor, date[:7]))  # match on actor + YYYY-MM

        existing_urls_list = "\n".join(f"- {u}" for u in sorted(existing_urls)) if existing_urls else "  (none yet)"

        search_prompt = f"""
        You are a cybersecurity analyst specializing in APT (Advanced Persistent Threat) intelligence.

        Search the web for APT attack technical reports published AFTER {latest_date}. 
        Look for detailed threat intelligence reports from reliables sources like Mandiant, CrowdStrike, Securelist (Kaspersky), ESET, Microsoft Security Blog, Palo Alto, and other reputable cybersecurity vendors.

        IMPORTANT — the following report URLs are already in the database. Do NOT include any of these in your results:
        {existing_urls_list}

        For each relevant APT technical report you find (aim for 2 reports only), extract the following structured information.

        After completing all your searches, output your findings as a JSON array wrapped in <json> tags at the very end of your response. For each technical report you should identify the following properties:

        {{
        "date": "publication date in YYYY-MM-DD format",
        "download_url": "full URL of the report",
        "source": "the technical report publisher (e.g., CheckPoint, Palo Alto Networks)",
        "cve": "comma-separated CVE IDs mentioned in the report, or N/A",
        "zero_day": "TRUE if a zero-day was exploited, FALSE if not, N/A if not mentioned",
        "threat_actor": "name of the APT group or threat actor, or N/A",
        "threat_country": "country the threat actor is attributed to, or N/A. The country name should be in 2-letter format (e.g., US, RU, CN)",
        "victims": "countries being targeted, or N/A. Country names should strictly follow the 2-letter format (e.g., US, RU, CN)",
        "attack_vector": "initial attack vectors and techniques used, or N/A. Group them into one of followings: Spear Phishing, Phishing, Watering Hole, Credential Reuse, Social Engineering, Exploit Vulnerability, Malicious Documents, Covert Channels, Drive-by Download, Removable Media, Website Equipping, Meta Data Monitoring.",
        "malware": "specific malware, tool names, or software frameworks used in the attack from this report, or N/A",
        "start_date": "start date of the attack campaign in YYYY-MM-DD format, or empty string if unknown. If the information is known till the month, approximate the date to be the 15th day of the month.",
        "end_date": "end date of the attack campaign in YYYY-MM-DD format, or empty string if unknown. If the information is known till the month, approximate the date to be the 15th day of the month.",
        "duration": "total duration of the campaign in days as a number, or N/A if unknown",
        "target_sectors": "targeted sectors, or N/A. Group them into one of followings: Government and defense agencies, Corporations and Businesses, Financial institutions, Healthcare, Energy and utilities, Cloud/IoT services, Manufacturing, Education and research institutions, Media and entertainment companies, Critical infrastructure, Non-Governmental Organizations (NGOs) and Nonprofits, Individuals."
        }}

        Rules:
        - Only include detailed technical APT incident reports (not news summaries or opinion pieces)
        - Only include reports published strictly after {latest_date}
        - Do NOT include any URL from the already-in-database list above
        - Use N/A for any field where information is not available
        - Output the complete JSON array inside <json> ... </json> tags at the end
        """

        if not CLAUDE_CLI:
            _write_job(job_id, {
                "status": "error",
                "error": "Claude Code CLI not found. Make sure `claude` is installed and on PATH.",
            })
            return

        result = subprocess.run(
            [CLAUDE_CLI, "-p", search_prompt, "--allowedTools", "WebSearch,WebFetch"],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            _write_job(job_id, {
                "status": "error",
                "error": result.stderr.strip() or "Claude Code returned a non-zero exit code.",
            })
            return

        response_text = result.stdout

        json_match = re.search(r"<json>(.*?)</json>", response_text, re.DOTALL)
        if json_match:
            json_str = json_match.group(1).strip()
        else:
            json_match = re.search(r"\[.*\]", response_text, re.DOTALL)
            if not json_match:
                _write_job(job_id, {
                    "status": "error",
                    "error": "Claude did not return structured results. Please try again.",
                })
                return
            json_str = json_match.group()

        json_str = re.sub(r"^```(?:json)?\n?", "", json_str.strip())
        json_str = re.sub(r"\n?```$", "", json_str.strip()).strip()

        try:
            extracted_entries = json.loads(json_str)
            if not isinstance(extracted_entries, list):
                extracted_entries = [extracted_entries]
        except json.JSONDecodeError:
            _write_job(job_id, {
                "status": "error",
                "error": "Failed to parse Claude's response. Please try again.",
            })
            return

        # Resolve threat actor names and countries against the reference lookup
        for item in extracted_entries:
            if not isinstance(item, dict):
                continue
            actor_raw = _clean_value(item.get("threat_actor", ""), "").strip()
            if actor_raw and actor_raw.lower() not in ("n/a", "not mentioned", ""):
                match = threat_actor_lookup.get(actor_raw.lower())
                if match:
                    primary_name, country = match
                    item["threat_actor"] = primary_name
                    if country and country != "N/A":
                        item["threat_country"] = country

        added_entries = []
        skipped = 0

        with excel_lock:
            df = read_apt_dataframe()
            existing_urls = set(df["Download Url"].dropna().astype(str))
            # Secondary dedup: same threat actor reported in the same month from a different URL
            existing_actor_months = set()
            for _, row in df.iterrows():
                actor = str(row.get("Threat Actor", "") or "").strip().lower()
                date = str(row.get("Date", "") or "").strip()
                if actor and actor not in ("n/a", "not mentioned") and len(date) >= 7:
                    existing_actor_months.add((actor, date[:7]))

            for item in extracted_entries:
                if not isinstance(item, dict):
                    continue

                url = _clean_value(item.get("download_url", ""), "")
                if not url or url in existing_urls:
                    skipped += 1
                    continue

                actor_key = _clean_value(item.get("threat_actor", ""), "").lower()
                date_key = _clean_value(item.get("date", ""), "")[:7]
                if (actor_key and actor_key not in ("n/a", "not mentioned")
                        and date_key
                        and (actor_key, date_key) in existing_actor_months):
                    skipped += 1
                    continue

                entry = {
                    "Date": _clean_value(item.get("date"), ""),
                    "Download Url": url,
                    "Source": _clean_value(item.get("source")),
                    "CVE": _clean_value(item.get("cve")),
                    "Zero-Day": _clean_value(item.get("zero_day")),
                    "Threat Actor": _clean_value(item.get("threat_actor")),
                    "Threat Country": _clean_value(item.get("threat_country")),
                    "Victims": _clean_value(item.get("victims")),
                    "New Start Date": _clean_value(item.get("start_date"), ""),
                    "New End Date": _clean_value(item.get("end_date"), ""),
                    "Duration": _clean_value(item.get("duration")),
                    "AttackVector": _clean_value(item.get("attack_vector")),
                    "Malware": _clean_value(item.get("malware")),
                    "Target Sectors": _clean_value(item.get("target_sectors")),
                }

                if entry["Date"]:
                    parsed = pd.to_datetime(entry["Date"], errors="coerce")
                    entry["Date"] = "" if pd.isna(parsed) else parsed.strftime("%Y-%m-%d")

                df = pd.concat(
                    [df, pd.DataFrame([entry], columns=ENTRY_COLUMNS)],
                    ignore_index=True,
                )
                existing_urls.add(url)
                if actor_key and date_key:
                    existing_actor_months.add((actor_key, date_key))
                added_entries.append({
                    "threatActor": entry["Threat Actor"],
                    "url": url,
                    "date": entry["Date"],
                })

            if added_entries:
                write_apt_dataframe(df)

        _write_job(job_id, {
            "status": "done",
            "added": len(added_entries),
            "skipped": skipped,
            "entries": added_entries,
        })

    except subprocess.TimeoutExpired:
        _write_job(job_id, {
            "status": "error",
            "error": "Claude Code timed out after 5 minutes. Try again.",
        })
    except Exception as e:
        _write_job(job_id, {"status": "error", "error": str(e)})


@app.route('/run-claude', methods=['POST'])
def run_claude_start():
    job_id = str(uuid.uuid4())
    _write_job(job_id, {"status": "running"})

    thread = threading.Thread(target=run_claude_job, args=(job_id,))
    thread.daemon = True
    thread.start()

    return jsonify({"jobId": job_id}), 202


@app.route('/run-claude/<job_id>', methods=['GET'])
def run_claude_status(job_id):
    job = _read_job(job_id)
    if job is None:
        return jsonify({"error": "Job not found."}), 404
    return jsonify(job), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=True, use_reloader=True)

