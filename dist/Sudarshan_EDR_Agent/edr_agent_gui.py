"""
Sudarshan EDR - Agent GUI launcher.

Run any time, as any logged-in user (no admin/root needed):
    python edr_agent_gui.py

Shows a plain, read-only window with what the background agent is
currently doing (connection state, whether collection is on/off, last
cycle result). Close it however you like with the [X] button - it has no
effect on the actual agent, which runs separately (installed as a
protected Windows Service / systemd unit via deploy/install_agent.py) and
keeps going regardless of whether this window is open or closed.

See edr/agent_gui.py for details.
"""

from edr.agent_gui import main

if __name__ == "__main__":
    main()
