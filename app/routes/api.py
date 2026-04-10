from flask import Blueprint, request, jsonify, current_app, render_template, render_template, request
from app import db
from app.database import Queues, Triggers
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import hmac
import uuid
from datetime import datetime, timezone, timedelta
import logging
import time
import json
from azure.cosmos import CosmosClient
from azure.storage.blob import BlobServiceClient
import uuid
import requests

bp = Blueprint('api', __name__, url_prefix='/api')

# --- GLOBAL COSMOS CLIENTS ---
cosmos_client = None
cosmos_db = None
container_henstillinger_old = None  # Partition Key: FakturaStatus
container_unified = None            # Partition Key: /id
blob_service_client = None


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
    global cosmos_client, cosmos_db, container_henstillinger_old, container_unified, blob_service_client

    limiter.init_app(app)
    app.register_blueprint(bp)

    cosmos_client = CosmosClient(
    app.config["COSMOS_URL"],
        credential=app.config["COSMOS_KEY"]
    )
    cosmos_db = cosmos_client.get_database_client(app.config["COSMOS_DB_NAME"])

    # Old Legacy Henstillinger Container
    container_henstillinger_old = cosmos_db.get_container_client(app.config["COSMOS_CONTAINER"])

    # New Unified Container (Partition Key: /id)
    container_unified = cosmos_db.get_container_client(app.config.get("COSMOS_COMBINED_CONTAINER"))
     # Initialize Azure Blob Client
    blob_service_client = BlobServiceClient.from_connection_string(app.config["AZURE_BLOB_CONNECTION"])
    
def get_old_henstilling_container():
    return container_henstillinger_old

def get_unified_container():
    return container_unified

def get_blob_service_client():
    return blob_service_client

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
    

@bp.route('/tilsynapp', methods=['POST'])
@limiter.limit("60 per minute")
def get_vejman_kassen_rows():
    api_key = request.headers.get('X-API-Key')
    if not safe_compare(api_key, current_app.config['API_KEY']):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    status = data.get("status")
    container = get_old_henstilling_container()
    if not status:
        return jsonify({"error": "Missing 'status' in request body"}), 400

    try:
        query = f"SELECT * FROM c WHERE c.FakturaStatus = @status ORDER BY c.Startdato DESC"
        parameters = [{"name": "@status", "value": status}]
        items = list(container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
        return jsonify(items)
    except Exception as e:
        current_app.logger.exception("Failed to fetch data from Cosmos")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@bp.route('/tilsynapp/update', methods=['POST'])
@limiter.limit("30 per minute")
def update_vejman_kassen():
    api_key = request.headers.get('X-API-Key')
    if not safe_compare(api_key, current_app.config['API_KEY']):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    if not data or "id" not in data:
        return jsonify({"error": "Missing 'id' field"}), 400

    user_email = data.get("userEmail")
    if not user_email or "@" not in user_email:
        return jsonify({"error": "Opdater din app"}), 426  # Upgrade Required
    # Normalize field names
    key_map = {
        "fakturaStatus": "FakturaStatus",
        "kvadratmeter": "Kvadratmeter",
        "tilladelsestype": "Tilladelsestype",
        "slutdato": "Slutdato",
    }

    updates = {}
    for k, v in data.items():
        if k in key_map:
            updates[key_map[k]] = v

    if not updates:
        return jsonify({"error": "No valid fields to update"}), 400

    old_status = data.get("oldStatus")
    new_status = updates.get("FakturaStatus", old_status)

    container = get_old_henstilling_container()

    # Build audit entry
    audit_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": user_email,
        "changes": updates
    }

    try:
        # ---------------------------------------------------
        # 1. STATUS CHANGE → CROSS PARTITION MOVE
        # ---------------------------------------------------
        if old_status and new_status and old_status != new_status:

            # Read old document
            item = container.read_item(item=data["id"], partition_key=old_status)

            # Audit log
            item.setdefault("AuditLog", []).append(audit_entry)

            # Apply updates + new status
            item.update(updates)
            item["FakturaStatus"] = new_status

            # Create in new partition
            container.create_item(body=item)

            # Remove old
            container.delete_item(item=data["id"], partition_key=old_status)

            return jsonify({"status": "success", "moved": True}), 200

        # ---------------------------------------------------
        # 2. SAME PARTITION → PATCH ITEM
        # ---------------------------------------------------
        # --- Same partition: patch with audit update ---
        partition_key = old_status or new_status or "Ny"

        # Read item first
        item = container.read_item(item=data["id"], partition_key=partition_key)

        # Build patch operations
        patch_ops = []

        # Add/replace updated fields
        for k, v in updates.items():
            op = "replace" if k in item else "add"
            patch_ops.append({
                "op": op,
                "path": f"/{k}",
                "value": v
            })

        # Always append audit log safely
        audit_log = item.get("AuditLog", [])
        audit_log.append(audit_entry)

        # ALWAYS use "add", never replace
        patch_ops.append({
            "op": "add",
            "path": "/AuditLog",
            "value": audit_log
        })

        # Apply patch
        container.patch_item(
            item=data["id"],
            partition_key=partition_key,
            patch_operations=patch_ops
        )
        return jsonify({"status": "success", "moved": False}), 200

    except Exception as e:
        current_app.logger.exception("Failed to update Cosmos document")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500

@bp.route("/tilsynapp/version", methods=["GET"])
def get_app_version_info():
    return jsonify({
        "min_version": 8,
        "latest_version": 8,
        "message": "Din app skal opdateres før du kan fortsætte. Gå ind i play store og søg efter nye opdateringer"
    })


def parse_iso_datetime(dt_string):
    """
    Parses an ISO 8601 string into a timezone-aware datetime object.
    Handles 'Z' suffix and '+HH:MM' offsets correctly.
    """
    if not dt_string:
        return None
    try:
        # Cosmos sometimes uses 'Z', fromisoformat expects '+00:00' in older 3.x versions
        clean_dt = dt_string.replace('Z', '+00:00')
        return datetime.fromisoformat(clean_dt)
    except (ValueError, TypeError):
        return None

@bp.route('/tilsyn/tasks', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def get_unified_tasks():
    # ... Auth check ...
    
    # Correct: Using the unified container client initialized at startup
    container = get_unified_container()
    
    now = datetime.now().astimezone()
    today_str = now.date().isoformat()

    try:
        # Fetch active permissions and 'Ny' henstillinger from TilsynItem
        query = "SELECT * FROM c WHERE (c.type = 'permission') OR (c.type = 'henstilling' AND c.FakturaStatus = 'Ny')"
        items = list(container.query_items(query=query, enable_cross_partition_query=True))

        result = []
        for item in items:
            last_insp_str = item.get('last_inspected_at')
            
            if item.get('type') == 'henstilling':
                # Henstilling: Simple daily logic
                if not last_insp_str or not last_insp_str.startswith(today_str):
                    result.append(item)
            else:
                # Permission: Reappearing logic based on end_date
                if not last_insp_str:
                    result.append(item)
                    continue
                
                last_insp_dt = parse_iso_datetime(last_insp_str)
                end_dt = parse_iso_datetime(item.get('end_date'))
                
                # 1. Show if not inspected today
                if last_insp_dt and last_insp_dt.date() < now.date():
                    result.append(item)
                # 2. Reappear if it's past the end time today AND last inspection was before that end time
                elif end_dt and end_dt.date() == now.date() and now >= end_dt:
                    if last_insp_dt and last_insp_dt < end_dt:
                        result.append(item)
        
        result.sort(key=lambda x: x.get('street_name') or x.get('Adresse') or "")
        return jsonify(result), 200

    except Exception as e:
        current_app.logger.exception("Unified tasks failed")
        return jsonify({"error": str(e)}), 500

@bp.route('/tilsyn/history', methods=['GET', 'POST'])
@limiter.limit("60 per minute")
def get_unified_history():
    api_key = request.headers.get('X-API-Key')
    if not safe_compare(api_key, current_app.config['API_KEY']):
        return jsonify({"error": "Unauthorized"}), 401

    container = get_unified_container()
    try:
        query = "SELECT * FROM c"
        result = list(container.query_items(query=query, enable_cross_partition_query=True))
        result.sort(key=lambda x: x.get('end_date') or x.get('Slutdato') or "", reverse=True)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/tilsyn/inspect', methods=['POST'])
@limiter.limit("60 per minute")
def unified_inspect():
    api_key = request.headers.get('X-API-Key')
    if not safe_compare(api_key, current_app.config['API_KEY']):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True)
    item_id = data.get("id")
    item_type = data.get("type")
    user_email = data.get("inspector_email")
    comment = data.get("comment")
    inspected_at = data.get("inspected_at") or datetime.now(timezone.utc).isoformat()

    if not item_id or not user_email:
        return jsonify({"error": "Missing required fields"}), 400

    container = get_unified_container()
    try:
        item = container.read_item(item=item_id, partition_key=item_id)

        item['last_inspected_at'] = inspected_at
        item['last_inspector_email'] = user_email
        item['inspection_comment'] = comment

        # Maintain History
        if 'inspections' not in item or not isinstance(item['inspections'], list):
            item['inspections'] = []
        
        item['inspections'].append({
            "inspected_at": inspected_at,
            "inspector_email": user_email,
            "comment": comment
        })

        if item_type == "henstilling":
            updates = data.get("updates", {})
            if "kvadratmeter" in updates: item["Kvadratmeter"] = updates["kvadratmeter"]
            if "slutdato" in updates: item["Slutdato"] = updates["slutdato"]
            if "fakturaStatus" in updates: item["FakturaStatus"] = updates["fakturaStatus"]
            
            item.setdefault("AuditLog", []).append({
                "timestamp": inspected_at, "user": user_email, "changes": updates
            })

        container.replace_item(item=item_id, body=item, if_match=item.get('_etag'))

        queue_payload = {
            "queue_name": "TilsynJournal",
            "reference": item_id,
            "data": data,  # Includes selection, comment, id, etc.
            "created_by": user_email
        }
        
        requests.post(
            f"{request.host_url.rstrip('/')}/api/queue",
            json=queue_payload,
            headers={"X-API-Key": request.headers.get('X-API-Key')},
            timeout=5
        )
        return jsonify({"status": "success"}), 200
    except Exception as e:
        current_app.logger.exception(f"Unified inspect failed for {item_id}")
        return jsonify({"error": str(e)}), 500

@bp.route('/tilsyn/upload-image', methods=['POST'])
@limiter.limit("100 per minute")
def upload_tilsyn_image():
    api_key = request.headers.get('X-API-Key')
    if not safe_compare(api_key, current_app.config['API_KEY']):
        return jsonify({"error": "Unauthorized"}), 401

    if 'image' not in request.files:
        return jsonify({"error": "No image provided"}), 400
    
    image_file = request.files['image']
    item_id = request.form.get('id')
    # Get the readable filename from the Android app (e.g. 20240520_143005_123.jpg)
    custom_filename = request.form.get('filename')
    
    try:
        # Use custom filename if provided, otherwise fallback to UUID
        file_part = custom_filename if custom_filename else f"{uuid.uuid4()}.jpg"
        blob_name = f"{item_id}/{file_part}"
        
        # 1. Upload to Azure
        blob_client = get_blob_service_client().get_blob_client(
            container="tilsyn-uploads", 
            blob=blob_name
        )
        blob_client.upload_blob(image_file.read(), overwrite=True)

        # 2. Call the queue endpoint
        queue_payload = {
            "queue_name": "TilsynBilleder",
            "reference": item_id,
            "data": {
                "tilsyn_id": item_id,
                "blob_path": blob_name,
                "filename": file_part # This is the readable name for the robot/journal
            },
            "created_by": "TilsynsApp"
        }
        
        requests.post(
            f"{request.host_url.rstrip('/')}/api/queue", 
            json=queue_payload,
            headers={"X-API-Key": api_key},
            timeout=5
        )

        return jsonify({"status": "success", "blob": blob_name}), 200

    except Exception as e:
        current_app.logger.exception("Upload failed")
        return jsonify({"error": str(e)}), 500