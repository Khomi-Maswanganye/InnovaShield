# InnovaShield — Patent & Trademark Intelligence Platform

## Overview
Real-time patent and trademark data synced automatically from **USPTO PatentsView API** and **USPTO Trademark TSDR API**. AI-powered insights, expiry alerts, and IP monitoring in one platform.

## Features
- Live patent & trademark search from USPTO
- Automatic 6-hour sync from official APIs
- Watchlist tracking with expiry alerts
- AI-generated industry trends and insights
- Expiring patents & trademarks dashboard

---

## Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Set Up Database
```bash
# Create MySQL database
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS innovashield;"

# Run the schema (create tables)
mysql -u root -p innovashield < schema.sql
```

### 3. Configure Environment
No special environment variables required for USPTO-only mode. The application works out of the box.

If you have custom DB credentials, create `.env`:
```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=innovashield
```

### 4. Start the Server
```bash
npm start
# or
node server.js
```

Visit: **http://localhost:3000**

---

## Database Schema

### patents
| Column | Type | Description |
|--------|------|-------------|
| patent_id | INT PK | Auto-increment ID |
| patent_number | VARCHAR(50) | Unique patent number |
| title | TEXT | Patent title |
| owner | VARCHAR(255) | Assignee/owner name |
| industry | VARCHAR(100) | Detected industry |
| filing_date | DATE | Filing date |
| expiry_date | DATE | Calculated expiry (20 yrs from filing) |
| status | ENUM('Active','Expired') | Current status |
| description | TEXT | Patent abstract |
| source | ENUM('USPTO') | Data source |
| created_at | TIMESTAMP | When record was added |

### trademarks
| Column | Type | Description |
|--------|------|-------------|
| trademark_id | INT PK | Auto-increment ID |
| trademark_number | VARCHAR(50) | Unique trademark number |
| name | TEXT | Trademark name/wordmark |
| owner | VARCHAR(255) | Applicant/owner name |
| industry | VARCHAR(100) | Detected industry |
| registration_date | DATE | Registration date |
| expiry_date | DATE | Calculated expiry (10 yrs from registration) |
| status | ENUM('Active','Pending','Renewed') | Current status |
| source | ENUM('USPTO') | Data source |
| created_at | TIMESTAMP | When record was added |

### watchlist
| Column | Type | Description |
|--------|------|-------------|
| watchlist_id | INT PK | Auto-increment ID |
| patent_id | INT FK | Linked patent (nullable) |
| trademark_id | INT FK | Linked trademark (nullable) |
| user_id | VARCHAR(100) | Who added it |
| notes | TEXT | User notes |
| created_at | TIMESTAMP | When added |

---

## API Sources

### Patents
| Source | API | Sync Frequency | Coverage |
|--------|-----|---------------|----------|
| 🇺🇸 USPTO | PatentsView API (`api.patentsview.org`) | Every 6 hours | US patents |

### Trademarks
| Source | API | Sync Frequency | Coverage |
|--------|-----|---------------|----------|
| 🇺🇸 USPTO | Trademark TSDR API (`developer.uspto.gov`) | Every 6 hours | US trademarks |

---

## Routes

### Public Pages
| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Home page with unified search (patents + trademarks) |
| `/patents` | GET | Patent database |
| `/trademarks` | GET | Trademark database |
| `/watchlist` | GET/POST | Track and monitor specific IP assets |
| `/expiring` | GET | Patents & trademarks expiring in next 180 days |
| `/alerts` | GET | Status updates (renewed, updated, pending) |
| `/trends` | GET | AI-generated industry insights |
| `/pricing` | GET | Pricing page |

### API Endpoints
| Route | Method | Description |
|-------|--------|-------------|
| `/api/sync` | POST | Trigger manual sync (body: `{ "topic": "AI" }`) |
| `/api/sync-status` | GET | Get last sync time and counts |
| `/api/patents` | GET | JSON all patents |
| `/api/trademarks` | GET | JSON all trademarks |

---

## Search Behavior

All search routes (`/`, `/patents`, `/trademarks`) trigger **on-demand synchronization** before querying the database. This ensures fresh results.

- First query after server start will take a few extra seconds (syncing)
- Subsequent queries are fast (database lookup only)
- Auto-sync runs every 6 hours in the background

### Search Parameters
- `q` – Keyword search across title/owner/number/industry
- `industry` – Filter by detected industry

---

## Development

### Project Structure
```
innovaShield/
├── server.js          # Express app + API sync functions
├── views/             # EJS templates
│   ├── index.ejs      # Home / unified search
│   ├── admin.ejs      # Admin dashboard (system summary)
│   ├── admin_users.ejs # User management (admin only)
│   ├── patents.ejs    # Patent list (admin only)
│   ├── trademarks.ejs # Trademark list (admin only)
│   ├── watchlist.ejs  # Watchlist management
│   ├── expiring.ejs   # Expiry dashboard
│   ├── alerts.ejs     # Status alerts
│   ├── trends.ejs     # AI insights
│   ├── pricing.ejs    # Pricing page
├── public/
│   └── style.css      # Global styles + dark/light theme
├── package.json
└── schema.sql         # Database schema
```

### Key Functions (server.js)
- `syncUSPTO(query)` – Fetches US patents from PatentsView
- `syncTrademarks(query)` – Fetches US trademarks from USPTO TSDR
- `runAutoSync(topic)` – Master sync orchestrator, runs every 6h
- Routes: `/`, `/patents`, `/trademarks`, `/watchlist`, `/expiring`, `/alerts`, `/trends`

---

## Notes
- All data sourced from **USPTO** public APIs (no WIPO)
- Auto-sync runs every 6 hours; use `/api/sync` to force refresh
- Fire-and-forget sync on search ensures fresh results without delaying response
- The `source` column in both tables is ENUM('USPTO') only

---

## License
ISC

---

## Support
For issues, bug reports, or feature requests, contact: research@innovashield.com
