import os
import sys
import time
import servicemanager
import win32event
import win32service
import win32serviceutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from edr.config import DEFAULT_SERVER_URL, DEFAULT_INTERVAL_SECONDS 
import edr.agent as agent_mod  


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
            pass  

        agent_mod.agent_status.write_status(agent_id=agent_id, server=server, state="connected")

        controller = agent_mod.AgentController(server, agent_id)
        controller.start()

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
