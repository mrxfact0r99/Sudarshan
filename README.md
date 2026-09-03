# Sudarshan - Rapid Digital Evidence Triage Toolkit
A lightweight, cross-platform (Windows / Linux) toolkit for
quickly collecting common live-triage digital forensic artifacts and
generating a PDF investigation report from them.

## Installation Process
```
git clone https://github.com/mrxfact0r99/Sudarshan.git
```
OR

Download the zip file and after that extract and open in terminal 

``` 
cd Sudarshan
```

```
pip3 install -r requirements.txt
```

## Run

**Command line:**
```
python3 main.py
```

**Graphical interface:**
```
python3 main_gui.py
```

## EDR Mode (agent + central server)

Sudarshan can also run in a client/server "EDR" mode: a lightweight **agent**
runs on an endpoint and periodically uploads the same artifacts (processes,
network connections, USB/login events, browser history, system logs, recycle
bin, clipboard snapshot, command history, executed programs) to a central
**server** you run on your own network, which shows a dashboard per endpoint
and can generate the same PDF report per endpoint on demand.

> **Authorized use only.** Only run the agent on machines you own or have
> explicit authorization to monitor (your own lab VMs, a spare device, a
> college lab demo). This is the same rule real EDR products follow — the
> agent is installed openly by whoever administers the machine, never
> secretly on someone else's device. See `edr/config.py` for details.

**1. Start the server** (on the machine that will act as your console):
```
export SUDARSHAN_ENROLL_TOKEN="pick-a-real-secret"
python3 -m edr.server
```
This starts a dashboard at `http://<server-ip>:8443`. Opening it now asks
for a **password** before showing any endpoint data — the `X-Agent-Token`
above is a *separate* secret that only agents use to talk to the API; it
does not let you into the dashboard in a browser.

**The dashboard password is one line in `edr/config.py`:**
```python
DASHBOARD_PASSWORD = os.environ.get("SUDARSHAN_DASHBOARD_PASSWORD", "sudarshan123")
```
To change it, either edit `"sudarshan123"` to whatever you want, or set
`SUDARSHAN_DASHBOARD_PASSWORD` as an environment variable before starting
the server (the env var wins if both are set). No username - just the one
password.

**2. Connect the agent** (on each endpoint you're authorized to monitor, on
the same WiFi/LAN):
```
export SUDARSHAN_ENROLL_TOKEN="the-same-secret-as-above"
python3 -m edr.agent --server http://<server-ip>:8443
```
The endpoint user only needs to start/connect the agent. After connection,
the **dashboard controls collection Start/Stop and the collection interval**.
The agent sends a heartbeat every few seconds, so closing the agent window
causes the endpoint to become **Offline** on the dashboard.

**3. Control endpoints from the dashboard**
- **Online / Offline** shows whether the agent process is still connected.
- **Start / Stop** controls telemetry collection without remotely executing
  arbitrary commands.
- **Interval** changes the collection period (10 seconds to 24 hours).
- If the agent process is closed, the server stops receiving heartbeats and
  marks it Offline automatically.
- If collection is stopped from the dashboard, the agent remains connected
  and Online but does not run collection cycles until Start is pressed.

**4. View endpoints and reports** from the dashboard in a browser — click
into an endpoint to see every collection cycle. As soon as a cycle finishes
uploading, its PDF report is **generated automatically in the background**
(no button click needed). Each cycle is stored in its own numbered folder
on the server:

```
edr/server_data/agents/<agent_id>/cycles/cycle_0001/Evidences/*.json
edr/server_data/agents/<agent_id>/cycles/cycle_0001/Report/*.pdf
edr/server_data/agents/<agent_id>/cycles/cycle_0002/Evidences/*.json
edr/server_data/agents/<agent_id>/cycles/cycle_0002/Report/*.pdf
...
```

so a later collection cycle never overwrites an earlier one. The dashboard's
"Generate Report" button per cycle is only there to re-run/regenerate that
one cycle's PDF on demand.

The agent only ever pushes data to the server; the server never sends
commands back down to an agent.

### Giving someone just the agent (no server code)

If you need to hand the agent to someone else's machine without also
handing over the server (dashboard, report generator, other agents' data),
build the agent-only release:
```
python3 build_agent_release.py
```
This copies only `edr/agent.py`, `edr/agent_gui.py`, `edr/config.py`,
`edr_agent_gui.py`, and `Scripts/collectors/*` (plus `Scripts/common.py`)
into `dist/Sudarshan_EDR_Agent/` and zips it — no `edr/server.py`,
`edr/server_gui.py`, dashboard templates, report generator, or server
database ever leave the project folder.

### Using the GUI instead of the terminal

Both sides also have a Tkinter GUI, so you don't have to type commands:

- **Server machine:** run `python3 edr_server_gui.py` (or `python edr_server_gui.py` on
  Windows). Enter the same enroll token and a port, click **Start Server**, then
  **Open Dashboard**.
- **Agent machine (e.g. the Windows laptop):** run `python edr_agent_gui.py`. Enter the
  server URL (`http://<server-ip>:8443`) and the same token, then click **Start Agent**.
  The endpoint stays connected with a heartbeat; use the server dashboard to Start/Stop
  collection and change the interval. Closing the agent makes it Offline. **Run Once**
  remains available for a one-time local test.