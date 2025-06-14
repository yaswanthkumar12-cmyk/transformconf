from flask import Flask, render_template, request, jsonify
from datetime import datetime
import re
import pandas as pd

app = Flask(__name__)

# In-memory IP quota tracker and seen IPs
usage_tracker = {}
seen_ips = set()

def get_client_ip():
    """Get real client IP behind proxies like Render"""
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        # Sometimes multiple IPs, take first
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip
def check_quota(ip):
    # Bypass quota for localhost or internal IPs
    if ip in ("127.0.0.1", "::1"):
        return True

    today = datetime.utcnow().date()
    record = usage_tracker.get(ip, {"count": 0, "date": today})

    if record["date"] != today:
        record = {"count": 0, "date": today}

    if record["count"] >= 1:
        return False

    record["count"] += 1
    usage_tracker[ip] = record
    return True

def smart_tokenize(line):
    pattern = r'"[^"]*"|\[[^\]]*\]|\{[^\}]*\}|\S+'
    return re.findall(pattern, line)

def classify_token_type(tokens):
    tokens = [t for t in tokens if t]
    if not tokens:
        return r'(\S+)', 'generic'

    if all(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', t) for t in tokens):
        return r'(\d{1,3}(?:\.\d{1,3}){3})', 'ip'

    if all(re.fullmatch(r'\d{4}-\d{2}-\d{2}', t) for t in tokens):
        return r'(\d{4}-\d{2}-\d{2})', 'date'

    if all(re.fullmatch(r'\d{2}:\d{2}:\d{2}(?:\.\d+)?', t) for t in tokens):
        return r'(\d{2}:\d{2}:\d{2}(?:\.\d+)?)', 'time'

    if all(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?', t) for t in tokens):
        return r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)', 'datetime'

    log_levels = {'info', 'warn', 'warning', 'error', 'debug', 'critical'}
    if all(t.lower() in log_levels for t in tokens):
        return r'(\b(?:INFO|WARN|WARNING|ERROR|DEBUG|CRITICAL)\b)', 'loglevel'

    if all(t.startswith('"') and t.endswith('"') for t in tokens):
        return r'"(.*?)"', 'quoted'

    if all(t.startswith('[') and t.endswith(']') for t in tokens):
        return r'\[(.*?)\]', 'bracketed'

    if all(t.startswith('{') and t.endswith('}') for t in tokens):
        return r'\{(.*?)\}', 'braced'

    if all(re.fullmatch(r'\d+', t) for t in tokens):
        return r'(\d+)', 'number'

    if all(t == '-' for t in tokens):
        return r'\-', 'hyphen'

    return r'(\S+)', 'generic'

def infer_regex_from_logs(log_lines):
    tokenized_logs = [smart_tokenize(line) for line in log_lines]
    max_len = max(len(tokens) for tokens in tokenized_logs)

    df_tokens = pd.DataFrame([
        tokens + [None] * (max_len - len(tokens))
        for tokens in tokenized_logs
    ])

    regex_parts = []
    format_parts = []
    field_count = 1
    used_names = set()

    heuristic_names = {
        0: 'month',
        1: 'day',
        2: 'time',
        3: 'host',
        4: 'program',
    }

    def make_unique_field_name(base_name):
        name = base_name
        counter = 2
        while name in used_names:
            name = f"{base_name}{counter}"
            counter += 1
        used_names.add(name)
        return name

    def name_field(i, tokens):
        tokens = [t for t in tokens if t]
        lowered = [t.lower() for t in tokens]

        if all(re.fullmatch(r'\d{2}:\d{2}:\d{2}(?:\.\d+)?', t) for t in tokens):
            return 'time'
        if all(re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', t) for t in tokens):
            return 'ip'
        if all(re.fullmatch(r'\w+\[\d+\]:?', t) for t in tokens):
            return 'program'
        if any(a in lowered for a in {'accepted', 'failed', 'connection', 'closed', 'started', 'stopped'}):
            return 'action'
        if any(t == 'for' for t in lowered):
            return 'user'
        if all(t.startswith('[') and t.endswith(']') for t in tokens):
            return 'bracketed'
        if all('/' in t or '.' in t for t in tokens):
            return 'path'
        if all(t in {'info', 'warn', 'error', 'debug', 'critical'} for t in lowered):
            return 'loglevel'
        return 'field'

    for i in range(max_len):
        tokens_at_pos = df_tokens[i].dropna().tolist()

        if tokens_at_pos and all(t == tokens_at_pos[0] for t in tokens_at_pos):
            token = tokens_at_pos[0]
            regex_parts.append(r'\-' if token == '-' else re.escape(token))
        else:
            regex_part, _ = classify_token_type(tokens_at_pos)
            regex_parts.append(regex_part)

            base_name = heuristic_names.get(i)
            if not base_name:
                base_name = name_field(i, tokens_at_pos)

            unique_name = make_unique_field_name(base_name)
            format_parts.append(f"{unique_name}::$$" + str(field_count))
            field_count += 1

    regex = r"\s+".join(regex_parts)
    regex = f"^{regex}$"
    format_str = " ".join(format_parts)

    return regex, format_str

def apply_field_mapping(format_str, field_mapping):
    parts = format_str.split()
    new_parts = []

    for part in parts:
        if "::$$" in part:
            auto_name, field_num = part.split("::$$")
            field_num_int = int(field_num)
            if field_num_int in field_mapping:
                new_name = field_mapping[field_num_int]
                new_parts.append(f"{new_name}::$$" + field_num)
            else:
                new_parts.append(part)
        else:
            new_parts.append(part)

    return " ".join(new_parts)

@app.route('/')
def index():
    ip = get_client_ip()
    seen_ips.add(ip)
    return render_template('transform_conf.html')

@app.route('/generate', methods=['POST'])
def generate_regex():
    ip = get_client_ip()
    seen_ips.add(ip)

    if not check_quota(ip):
        return jsonify({'result': f"❌ Quota exceeded for IP {ip}. Only 1 regex generations allowed per day. Better to change the network"})

    data = request.get_json()
    stanza = data.get('stanza', 'custom_log_extract').strip()
    field_mapping_raw = data.get('field_mapping', {})

    field_mapping = {}
    for k, v in field_mapping_raw.items():
        try:
            field_mapping[int(k)] = v
        except:
            pass

    def process_logs(log_lines, stanza_name):
        if len(log_lines) < 2:
            return f"[{stanza_name}]\n❌ Error: At least 2 log lines required."
        if len(log_lines) > 10:
            return f"[{stanza_name}]\n❌ Error: No more than 10 log lines allowed."

        regex, fmt = infer_regex_from_logs(log_lines)

        if field_mapping:
            fmt = apply_field_mapping(fmt, field_mapping)

        return f"""[{stanza_name}]
REGEX = {regex}
FORMAT = {fmt}
DEST_KEY = _raw
"""

    if 'groups' in data:
        results = []
        for group in data['groups']:
            logs_raw = group.get('logs', '').strip()
            source_name = group.get('source', '').strip()
            stanza_name = source_name if source_name else stanza
            log_lines = [line.strip() for line in logs_raw.splitlines() if line.strip()]
            results.append(process_logs(log_lines, stanza_name))
        return jsonify({'result': "\n\n".join(results)})

    logs_raw = data.get('logs', '').strip()
    log_lines = [line.strip() for line in logs_raw.splitlines() if line.strip()]
    result = process_logs(log_lines, stanza)
    return jsonify({'result': result})

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
