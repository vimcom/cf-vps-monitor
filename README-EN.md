# cf-vps-monitor
[简体中文](https://github.com/kadidalax/cf-vps-monitor/blob/main/README.md) | [English](https://github.com/kadidalax/cf-vps-monitor/blob/main/README-EN.md)
## VPS monitoring probe + website detection panel built with Cloudflare Worker.
## ⚠️First Thing First: This project is for learning and entertainment purposes only. Data accuracy and reliability are not guaranteed. Use with caution in production environments.
Panel Demo: https://vps-monitor.abo-vendor289.workers.dev/

PC Frontend:

![image](https://github.com/user-attachments/assets/bca3c2c5-b5cd-45fe-bada-c617194e4d6e)

Mobile Frontend:

![image](https://github.com/user-attachments/assets/4b438c11-2c1c-4190-b529-a9e109f1d03d)

Backend:

![image](https://github.com/user-attachments/assets/ddbae326-200b-4f4d-adf9-b295f2ac52d6)

VPS Side:

![image](https://github.com/user-attachments/assets/947a8853-f5de-49f6-93e0-86464310817b)


# VPS Monitoring Panel (Cloudflare Worker + D1 Version) - Deployment Guide

This is a simple VPS monitoring panel deployed on Cloudflare Workers, using Cloudflare D1 database for data storage. This guide will walk you through the deployment process using the Cloudflare **web dashboard**, without requiring command-line tools.

## Prerequisites

*   A Cloudflare account.

## Deployment Steps

### 1. Create D1 Database

You need a D1 database to store panel data (server list, API keys, monitoring data, etc.).

1.  Log in to the Cloudflare dashboard.
2.  In the left sidebar, find and click `Storage & Databases`.
3.  In the dropdown menu, select `D1 SQL Database`.
4.  Click `Create database`.
5.  Name your database (e.g., `vps-monitor-db`), then click `Create`.
6.  **Important: Initialize database tables**
    *   After the database is created, you'll see the database overview page. Click the `Console` tab.
    *   Copy the SQL commands below, paste them into the console input box, then click `Execute`:

```
CREATE TABLE IF NOT EXISTS admin_credentials (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_login INTEGER,
  failed_attempts INTEGER DEFAULT 0,
  locked_until INTEGER DEFAULT NULL,
  must_change_password INTEGER DEFAULT 0,
  password_changed_at INTEGER DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  api_key TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  sort_order INTEGER,
  last_notified_down_at INTEGER DEFAULT NULL,
  is_public INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS metrics (
  server_id TEXT PRIMARY KEY,
  timestamp INTEGER,
  cpu TEXT,
  memory TEXT,
  disk TEXT,
  network TEXT,
  uptime INTEGER,
  FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS monitored_sites (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  name TEXT,
  added_at INTEGER NOT NULL,
  last_checked INTEGER,
  last_status TEXT DEFAULT 'PENDING',
  last_status_code INTEGER,
  last_response_time_ms INTEGER,
  sort_order INTEGER,
  last_notified_down_at INTEGER DEFAULT NULL,
  is_public INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS site_status_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL,
  timestamp INTEGER NOT NULL,
  status TEXT NOT NULL,
  status_code INTEGER,
  response_time_ms INTEGER,
  FOREIGN KEY(site_id) REFERENCES monitored_sites(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_site_status_history_site_id_timestamp ON site_status_history (site_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS telegram_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  bot_token TEXT,
  chat_id TEXT,
  enable_notifications INTEGER DEFAULT 0,
  updated_at INTEGER
);

INSERT OR IGNORE INTO telegram_config (id, bot_token, chat_id, enable_notifications, updated_at) VALUES (1, NULL, NULL, 0, NULL);

CREATE TABLE IF NOT EXISTS app_config (
  key TEXT PRIMARY KEY,
  value TEXT
);

INSERT OR IGNORE INTO app_config (key, value) VALUES ('vps_report_interval_seconds', '60');
```

 *   You should normally see `This query executed successfully. Response time 1090ms, query time 0.24ms`. Your database table structure is now ready.

### 2. Create and Configure Worker

Next, create a Worker and deploy the code.

1.  In the left sidebar, click `Compute (Workers)`, then select `Workers & Pages`.
2.  On the overview page, click `Create`.
3.  Select `Start with Hello World!` and click `Get started`.
4.  Name your Worker (e.g., `vps-monitor-worker`), ensure the name is available.
5.  Click `Deploy`.
6.  After deployment, click `Edit code` to enter the Worker editor.
7.  **Delete all existing code** in the editor.
8.  Open the `worker.js` file from this repository and copy **all** its content.
9.  Paste the copied code into the Cloudflare Worker editor.
10. Click the `Deploy` button in the top-right corner of the editor.

### 3. Bind D1 Database to Worker

The Worker needs access to the D1 database you created earlier.

1.  On the Worker management page (click the Worker name above the edit code page to return to the management page), select the `Bindings` tab.
2.  Select `D1 database`.
3.  Enter `DB` (must be uppercase) in the `Variable name` field.
4.  In the `D1 database` dropdown, select the database you created earlier (e.g., `vps-monitor-db`).
5.  Click `Deploy`.

### 4. Add Environment Variables

In `Settings` → `Variables and secrets`, add the following environment variables for enhanced security:
1. Variable name: `JWT_SECRET`, Type: `Secret`, Value: `Any random string of about 30 characters`
2. Save and deploy after adding

### 5. Set Trigger Frequency (for website monitoring)

1.  On the Worker management page, select the `Settings` tab.
2.  In the settings page, select the `Triggers` submenu.
3.  Click `Add`, then select `Cron trigger`.
4.  Select `Schedule`, set the Worker execution frequency to `hourly`, and enter 1 in the box below (i.e., check websites every hour on the hour).
5.  Click `Add`.

### 6. Access the Panel

After deployment and binding are complete, your monitoring panel should be accessible via the Worker's URL.

*   On the settings page, you'll see a `.workers.dev` URL, e.g., `vps-monitor.abo-vendor289.workers.dev`.
*   Open this URL in your browser, and you should see the monitoring panel's frontend interface.

## Using the Panel

### 1. Initial Login

1.  Visit your Worker URL.
2.  Click `Login` in the top-right corner of the page or directly access the `/login` path (e.g., `https://vps-monitor.abo-vendor289.workers.dev/login`).
3.  Use the credentials to log in:
    *   Username: `admin`
    *   Password: `monitor2025!`
4.  After logging in, change the password immediately!!!

### 2. Add Servers

1.  After logging into the backend, you should see the management interface.
2.  Find the option to add a server.
3.  Enter the server name and optional description.
4.  Click `Save`.
5.  The panel will automatically generate a unique `Server ID` and `API Key`. **Please note down this Server ID and API Key**, as they are needed when deploying the Agent.

### 3. Deploy Agent (Probe)

The Agent is a script that needs to run on your VPS to collect status information and send it back to the panel.

There are two ways to install the Agent script:

The first method is to directly copy the command with parameters from the backend for one-click installation (recommended):
![image](https://github.com/user-attachments/assets/11e3c3bf-84c1-41ec-ae67-310c566830b3)

The second method is to download and run the script:
```
wget https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh -O cf-vps-monitor.sh && chmod +x cf-vps-monitor.sh && ./cf-vps-monitor.sh
```
Or download and run the script:
```
curl -O https://raw.githubusercontent.com/kadidalax/cf-vps-monitor/main/cf-vps-monitor.sh && chmod +x cf-vps-monitor.sh && ./cf-vps-monitor.sh
```
*   Installation requires `Server ID`, `API Key`, and your `Worker URL`
*   You can click `View Key` in the backend to get these three parameters
*   Follow the prompts to complete the installation. After installation, the Agent will start sending data to your panel regularly. You should see status updates for the corresponding server on the panel.

### 4. Agent Management

The installation script itself also provides management functions:

*   **Install service:**
*   **Uninstall service:**
*   **View status:**
*   **View logs:**
*   **Stop service:**
*   **Restart service:**
*   **Modify configuration:**

### 5. Add Monitored Websites

1.  After logging into the backend, you should see the management interface.
2.  Click `Add Monitored Website`.
3.  Enter `Website Name (optional)` and `Website URL (e.g., https://example.com)`.
4.  Click `Save`.

### 6. Configure Telegram Notifications

1.  Create a bot with BotFather and get the `Bot Token`.
2.  Get your `ID` from `@userinfobot`.
3.  Fill in the above two items respectively.
4.  Enable notifications and click `Save Telegram Settings`.

## Notes

*   **Worker and D1 Daily Quotas:** Cloudflare Worker and D1 free tiers have limitations. Please refer to Cloudflare documentation for details.
*   **Security:** The default password is very insecure. Please change it immediately after first login. The API keys used by the Agent should also be kept secure.
*   **Error Handling:** If the panel or Agent encounters issues, you can check the Worker logs (in the Cloudflare dashboard Worker page) and Agent logs.
*   All content and code above are AI-generated. If you encounter problems, please take the code directly to an AI for help.

### Advertisement:
[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")
