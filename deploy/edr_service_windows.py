"""
Sudarshan EDR - Windows service wrapper.

Runs edr/agent_gui.py's worker loop (agent_mod.enroll + AgentController +
run_cycle) under the LocalSystem account instead of the logged-in user's
session. This is what actually enforces "only admin/root can end task":

  - A standard user's access token only carries PROCESS_TERMINATE rights
    over processes running under their OWN logon. It never has that
    right over a LocalSystem-owned process.
  - Task Manager -> End Task on this process (or `taskkill /PID ...`)
    will fail with "Access is denied" for a standard user.
  - An account in the local Administrators group CAN still end it,
    because Windows grants admins the elevated token that carries
    SeDebugPrivilege / cross-session terminate rights.

Install (run once, from an elevated/admin prompt):
    pip install pywin32
    python deploy\\edr_service_windows.py install
    python deploy\\edr_service_windows.py start

Uninstall:
    python deploy\\edr_service_windows.py stop
    python deploy\\edr_service_windows.py remove

Note: services have no desktop/session by default, so this runs the
headless agent loop (no Tkinter window) - agent_gui.py's window is for
interactive/manual runs. Status is visible on the EDR dashboard instead.
"""

import os
import sys
import time
import servicemanager
import win32event
import win32service
import win32serviceutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from edr.config import DEFAULT_SERVER_URL, DEFAULT_INTERVAL_SECONDS  # noqa: E402
import edr.agent as agent_mod  # noqa: E402


class SudarshanEDRService(win32serviceutil.ServiceFramework):
    _svc_name_ = "SudarshanEDRAgent"
    _svc_display_name_ = "Sudarshan EDR Agent"
    _svc_description_ = (
        "Endpoint telemetry agent for the Sudarshan EDR project. "
        "Runs as LocalSystem so it can only be stopped by an administrator."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        # Only reachable via the Services console / `sc stop` / `net stop`,
        # both of which require admin rights to act on a LocalSystem service.
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.main()

    def main(self):
        server = DEFAULT_SERVER_URL
        agent_id = agent_mod.load_or_create_agent_id()
        try:
            agent_id = agent_mod.enroll(server, agent_id)
        except Exception:
            pass  # dashboard will show endpoint offline; service keeps retrying below

        agent_mod.agent_status.write_status(agent_id=agent_id, server=server, state="connected")

        controller = agent_mod.AgentController(server, agent_id)
        controller.start()
        # Wait for the FIRST real heartbeat reply (server's actual
        # running/terminate state) instead of acting on the constructor's
        # guessed defaults for the first few seconds after every service
        # start/restart - same fix as edr/agent.py's main() uses for the
        # manual/systemd path, kept in sync here since this service loop
        # is a separate code path that reuses the same AgentController.
        controller.wait_until_ready(timeout=15)
        try:
            while self.running:
                running, interval, terminate = controller.snapshot()
                if terminate:
                    break
                if running:
                    try:
                        agent_mod.run_cycle(server, agent_id)
                    except Exception:
                        pass
                # Re-check every second (not just once per interval) so a
                # dashboard Terminate - or an admin `net stop` - takes
                # effect within ~1s instead of waiting up to `interval`
                # seconds (default 900s / 15 min) for the outer loop to
                # come back around.
                waited = 0
                while waited < interval and self.running:
                    if win32event.WaitForSingleObject(self.stop_event, 1000) == win32event.WAIT_OBJECT_0:
                        return
                    _, _, terminate = controller.snapshot()
                    if terminate:
                        return
                    waited += 1
        finally:
            controller.stop()


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(SudarshanEDRService)
