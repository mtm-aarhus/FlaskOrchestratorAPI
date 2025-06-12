# PyOrchestrator API

This is a secure internal API used to manage queue-based automation triggers.

## 🔐 Authentication

All endpoints require an `X-API-Key` header.
Requests without a valid API key will be rejected with a `401 Unauthorized` error.

**Example header:**

```
X-API-Key: your-secret-key
```

## 🚀 Endpoints

---

### POST /api/queue

Create a new queue item in the system.

**Required Header:**

```
Content-Type: application/json
X-API-Key: your-secret-key
```

**Request Body Fields:**

| Field          | Required | Description                                                                                                   | Default     |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------- | ----------- |
| `queue_name`   | ✅ Yes    | Name of the queue to push to (max 100 characters)                                                             | —           |
| `status`       | ❌ No     | One of: `NEW`, `IN_PROGRESS`, `DONE`, `FAILED`, `ABANDONED`                                                   | `NEW`       |
| `data`         | ❌ No     | Extra data as string, JSON object, or array. Automatically stringified. Max 2000 characters after conversion. | `null`      |
| `reference`    | ❌ No     | External reference ID (max 100 characters)                                                                    | `null`      |
| `message`      | ❌ No     | Human-readable notes or description                                                                           | `null`      |
| `created_by`   | ❌ No     | Identifier for the creating user/system (max 100 characters)                                                  | `null`      |
| `created_date` | ❌ No     | ISO8601 timestamp                                                                                             | Server time |

**Example Request:**

```json
{
  "queue_name": "SomeQueue",
  "status": "NEW",
  "data": {
    "case_id": "ABC123",
    "reference_id": "XYZ-001"
  },
  "reference": "ExternalRef-456",
  "created_by": "MySystem",
  "created_date": "2025-04-26T12:00:00",
  "message": "Created from external system"
}
```

**Response:**

```json
{
  "success": true,
  "id": "generated-uuid"
}
```

---

### POST /api/trigger

Update the `process_status` of a trigger (must be of type `SINGLE`).

**Required Header:**

```
Content-Type: application/json
X-API-Key: your-secret-key
```

**Request Body Fields:**

| Field            | Required | Description                                              | Default |
| ---------------- | -------- | -------------------------------------------------------- | ------- |
| `trigger_name`   | ✅ Yes    | Name of the trigger to update (must be of type `SINGLE`) | —       |
| `process_status` | ❌ No     | New status to assign (e.g. `IDLE`, `RUNNING`, `DONE`)    | `IDLE`  |

**Example Request:**

```json
{
  "trigger_name": "MyAutomationTrigger",
  "process_status": "IDLE"
}
```

**Response:**

```json
{
  "success": true,
  "trigger_name": "MyAutomationTrigger",
  "new_status": "IDLE"
}
```

---
### GET /vejmankassen

Fetch all rows from the `VejmanKassen` table filtered by `FakturaStatus`.

**Required Header:**

```
X-API-Key: your-secret-key
Content-Type: application/json
```

**Request Body:**

```json
{
  "status": "Ny"
}
```

**Response:**

```json
[
  {
    "Id": 1,
    "HenstillingId": "ABC123",
    "FakturaStatus": "Ny",
    "Adresse": "Example Street 1",
    ...
  },
  ...
]
```

---

### POST /vejmankassen/update

Update one or more fields on a specific row in the `VejmanKassen` table.

**Required Header:**

```
X-API-Key: your-secret-key
Content-Type: application/json
```

**Allowed Updatable Fields:**  
- `fakturaStatus`
- `kvadratmeter`
- `tilladelsestype`

**Request Body:**

```json
{
  "id": 42,
  "fakturaStatus": "Til fakturering",
  "kvadratmeter": 25.5,
  "tilladelsestype": "Henstilling Stillads m2"
}
```

**Response:**

```json
{
  "status": "success"
}
```

## ✅ Status Codes

| Code | Meaning                                   |
| ---- | ----------------------------------------- |
| 200  | Success (trigger updated)                 |
| 201  | Created (queue item added)                |
| 400  | Bad request or validation error           |
| 401  | Unauthorized (missing or invalid API key) |
| 403  | IP banned due to repeated failed attempts |
| 404  | Trigger not found or wrong type           |
| 429  | Rate limit exceeded                       |
| 500  | Server/database error                     |

---

## 🔒 Security Features

* API key authentication (`X-API-Key`)
* Brute-force protection with IP banning after 5 failed attempts
* Rate limiting per endpoint

| Endpoint       | Rate Limit           |
| -------------- | -------------------- |
| `/api/queue`   | 1000 requests/minute |
| `/api/trigger` | 10 requests/minute   |

---

## 🛠 Technology

* Python 3.11+ (Flask + Waitress)
* SQL Server via SQLAlchemy
* Hosted under IIS using httpPlatformHandler

---

## 📩 Contact

For internal access, credentials, or integration help, contact the automation development team.
