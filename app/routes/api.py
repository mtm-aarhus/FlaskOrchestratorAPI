from flask import Blueprint, request, jsonify, current_app, render_template
from app import db
from app.database import Queues, Triggers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hmac
import uuid
from datetime import datetime
import logging
import time
import json


bp = Blueprint('api', __name__, url_prefix='/api')

# Initialize Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["20 per minute"],  # General fallback
)

# Dynamic IP ban settings
FAILED_ATTEMPTS = {}
BANNED_IPS = {}
FAILED_ATTEMPT_WINDOW = 60  # seconds
FAILED_ATTEMPTS_THRESHOLD = 5
BAN_DURATION = 3600  # seconds (1 hour)
ALLOWED_STATUSES = {"NEW", "IN_PROGRESS", "DONE", "FAILED", "ABANDONED"}

# Safe compare for API keys
def safe_compare(a, b):
    return hmac.compare_digest(a or "", b or "")

# Helper to validate date fields
def parse_datetime(dt_string):
    if not dt_string:
        return None
    try:
        return datetime.fromisoformat(dt_string)
    except ValueError:
        raise ValueError(f"Invalid datetime format: {dt_string}")

# Register blueprint and limiter in create_app
def init_api(app):
    limiter.init_app(app)
    app.register_blueprint(bp)
    
@bp.route('/', methods=['GET'])
def api_documentation():
    return render_template('api/documentation.html')

@bp.before_request
def security_check():
    ip = request.remote_addr

    # 1. Check if IP is banned
    if ip in BANNED_IPS:
        ban_time = BANNED_IPS[ip]
        if time.time() < ban_time:
            logging.warning(f"Blocked banned IP: {ip}")
            return jsonify({"error": "Forbidden"}), 403
        else:
            # Unban after timeout
            del BANNED_IPS[ip]

@bp.route('/queue', methods=['POST'])
@limiter.limit("1000 per minute")
def create_queue_item():
    ip = request.remote_addr
    api_key = request.headers.get('X-API-Key')

    if not safe_compare(api_key, current_app.config['API_KEY']):
        logging.warning(f"Unauthorized attempt from {ip}")

        # Track failed attempts
        now = time.time()
        attempts = FAILED_ATTEMPTS.get(ip, [])

        # Only keep attempts within the defined time window
        attempts = [t for t in attempts if now - t < FAILED_ATTEMPT_WINDOW]
        attempts.append(now)
        FAILED_ATTEMPTS[ip] = attempts

        # Ban IP if too many failed attempts
        if len(attempts) >= FAILED_ATTEMPTS_THRESHOLD:
            BANNED_IPS[ip] = now + BAN_DURATION
            del FAILED_ATTEMPTS[ip]
            logging.warning(f"IP {ip} temporarily banned for {BAN_DURATION//60} minutes due to too many failed auth attempts.")

        return jsonify({"error": "Unauthorized"}), 401

    # Authorized - clear any old failed attempts
    FAILED_ATTEMPTS.pop(ip, None)

    try:
        data = request.get_json(force=True)
    except Exception:
        logging.warning(f"Invalid JSON attempt from {ip}")
        return jsonify({"error": "Invalid JSON"}), 400

    # ===== Input validation starts =====

    # queue_name (Required, max 100 chars)
    queue_name = data.get('queue_name')
    if not queue_name or len(queue_name) > 100:
        return jsonify({"error": "'queue_name' is required and must be <= 100 characters"}), 400

    # status (Optional, max 11 chars, defaults to 'NEW')
    status = data.get('status', 'NEW')
    if len(status) > 11 or status.upper() not in ALLOWED_STATUSES:
        return jsonify({"error": f"'status' must be one of {ALLOWED_STATUSES}"}), 400

    # reference (Optional, max 100 chars)
    reference = data.get('reference')
    if reference and len(reference) > 100:
        return jsonify({"error": "'reference' must be <= 100 characters"}), 400

    raw_data = data.get('data', None)

    # Convert dict/list to JSON string
    if isinstance(raw_data, (dict, list)):
        try:
            raw_data = json.dumps(raw_data, ensure_ascii=False)
        except Exception as e:
            return jsonify({"error": f"Failed to serialize 'data' field: {e}"}), 400

        # At this point, raw_data must be string or None
    if raw_data and not isinstance(raw_data, str):
        return jsonify({"error": "'data' must be a string, object, or list"}), 400

    if raw_data and len(raw_data) > 2000:
        return jsonify({"error": "'data' must be <= 2000 characters"}), 400

    # created_by (Optional, max 100 chars)
    created_by = data.get('created_by')
    if created_by and len(created_by) > 100:
        return jsonify({"error": "'created_by' must be <= 100 characters"}), 400

    # created_date (Optional, validate format)
    created_date_raw = data.get('created_date')
    try:
        created_date = parse_datetime(created_date_raw) if created_date_raw else datetime.now()
    except ValueError as e:
        return jsonify({"error parsing created date": str(e)}), 400

  

    # ===== Input validation ends =====

    queue_id = str(uuid.uuid4())

    fields = {
        'id': queue_id,
        'queue_name': queue_name,
        'status': status,
        'data': raw_data,
        'reference': reference,
        'created_date': created_date,
        'message': data.get('message'),
        'created_by': created_by
    }

    try:
        new_queue = Queues(**fields)
        db.session.add(new_queue)
        db.session.commit()
        return jsonify({"success": True, "id": queue_id}), 201
    except Exception as e:
        db.session.rollback()
        logging.error(f"Database error from {ip}: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500
    
@bp.route('/trigger', methods=['POST'])
@limiter.limit("10 per minute")  # You can increase this if needed
def trigger_update():
    ip = request.remote_addr
    api_key = request.headers.get('X-API-Key')

    # 🔐 Safe API key check with brute-force blocking
    if not safe_compare(api_key, current_app.config['API_KEY']):
        logging.warning(f"Unauthorized attempt from {ip}")

        # Track failed attempts
        now = time.time()
        attempts = FAILED_ATTEMPTS.get(ip, [])
        attempts = [t for t in attempts if now - t < FAILED_ATTEMPT_WINDOW]
        attempts.append(now)
        FAILED_ATTEMPTS[ip] = attempts

        if len(attempts) >= FAILED_ATTEMPTS_THRESHOLD:
            BANNED_IPS[ip] = now + BAN_DURATION
            del FAILED_ATTEMPTS[ip]
            logging.warning(f"IP {ip} temporarily banned for {BAN_DURATION//60} minutes due to too many failed auth attempts.")

        return jsonify({"error": "Unauthorized"}), 401

    # Authorized — clear old failed attempts
    FAILED_ATTEMPTS.pop(ip, None)

    # 🧾 Parse request
    try:
        payload = request.get_json(force=True)
    except Exception:
        logging.warning(f"Invalid JSON from {ip}")
        return jsonify({"error": "Invalid JSON"}), 400

    trigger_name = payload.get("trigger_name")
    if not trigger_name:
        return jsonify({"error": "'trigger_name' is required"}), 400

    new_status = payload.get("process_status", "IDLE")


    try:
        # Only update if type is 'SINGLE'
        trigger = db.session.query(Triggers).filter_by(trigger_name=trigger_name, type='SINGLE').first()
        if not trigger:
            return jsonify({"error": f"No SINGLE trigger found with name '{trigger_name}'"}), 404

        trigger.process_status = new_status
        db.session.commit()

        return jsonify({
            "success": True,
            "trigger_name": trigger_name,
            "new_status": new_status,
        }), 200

    except Exception as e:
        db.session.rollback()
        logging.error(f"Database error from {ip}: {str(e)}")
        return jsonify({"error": "Database error", "details": str(e)}), 500