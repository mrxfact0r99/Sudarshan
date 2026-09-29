# Sudarshan:
A lightweight, cross-platform (Windows / Linux) toolkit with EDR support for
quickly collecting common live-triage digital forensic artifacts and
generating a PDF investigation report from them.

# Disclaimer:
> **The creator of this tool is not responsible for any illegal activity committed with it, so please use it legally and take full responsibility for your actions**

## Installation Process:
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

## Run as Forensics Toolkit:

**Command line:**
```
python3 main.py
```

**Graphical interface:**
```
python3 main_gui.py
```

## Run as EDR Mode (agent + central server):

Sudarshan can also run in a client/server "EDR" mode: a lightweight **agent**
runs on an endpoint and periodically uploads the same artifacts (processes,
network connections, USB/login events, browser history, system logs, recycle
bin, clipboard snapshot, command history, executed programs) to a central
**server** you run on your own network, which shows a dashboard per endpoint
and can generate the same PDF report per endpoint on demand.

Sudarshan has strong security feture only admin or dashboard user have the powers that means once the agent is deployed in agent's system only system admin or dashboard user can uninstall/delete/kill the agent process normal user cannot terminate that process.

> **Authorized use only.** Only run the agent on machines you own or have
> explicit authorization to monitor (your own lab VMs, a spare device, a
> college lab demo). This is the same rule real EDR products follow — the
> agent is installed openly by whoever administers the machine, never
> secretly on someone else's device.
> The creator of this tool is not responsible for any illegal activity committed with it, so please use it legally and take full responsibility for your actions

**1. Create agent files**:
```
python3 build_agent_release.py
```

```
cd dist
```

Send the zip file to agent pc wich present in same network


**2. Start Server**:
```
python3 edr_server_gui.py
```
Enroll the token and start the server then copy the ip address and port number of running server

**3. Start agent in agent device**
 ```
 python3.exe .\deploy\install_agent.py --server http://{ip}:{port} --token {token}
 ```

**4. Open the dashboard and view endpoints and reports from the dashboard in a browser**

