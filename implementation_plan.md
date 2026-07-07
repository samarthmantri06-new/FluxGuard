# FluxGuard — Beginner's Step-by-Step Test Plan (Ubuntu VM)

This guide assumes you have **never used a Linux VM before**. Follow it slowly, one box at a
time. Copy each command, paste it into the terminal, press **Enter**, and read the
"✅ What you should see" note before moving on. If something looks wrong, jump to
**"❌ If it breaks"** at the bottom.

---

## First, some words you will keep seeing (read once)

| Word | What it actually means (plain English) |
|------|----------------------------------------|
| **Terminal** | The black window where you type commands. In Ubuntu, open it with `Ctrl + Alt + T`. |
| **Command** | One line of text you type and run by pressing Enter. |
| **`sudo`** | "Do this as administrator." It will ask for your VM password the first time. **You won't see the password as you type — that's normal.** Type it and press Enter. |
| **VM** | The pretend computer (Ubuntu) running inside your real computer (Windows). Everything here happens inside the VM. |
| **Project folder** | Where FluxGuard's files live: `/home/samarth/fluxguard`. |
| **XDP / eBPF** | The tiny program that runs *inside Linux* and blocks attack traffic. You don't edit it, you just load it. |
| **netns (network namespace)** | A fake mini-network we build inside the VM so we can attack ourselves safely. It has 3 parts: **client** (the attacker), **fluxguard** (our shield), **backend** (the server we protect). |
| **map** | A table the Linux program uses to remember blocked IPs, counters, etc. |
| **pin** | Save a map to a folder path so our Python tools can find it. |

**The 3 fake computers and their addresses (remember this picture):**

```
   client            fluxguard (our shield)          backend
 10.0.1.1  ───────►  10.0.1.2 / 10.0.2.1  ───────►  10.0.2.2
 (attacker)          (runs FluxGuard)               (server we protect)
```

**Two rules that save you pain:**
1. Do everything **inside the Ubuntu VM**, never on Windows.
2. You will need **several terminal windows open at once** in Stage 4 (one keeps FluxGuard
   running, the others run attacks). To open a new one: `Ctrl + Alt + T` again, or right-click
   the terminal → "Open Tab".

---

## Stage 0 — Get the VM ready (do this once)

**What this does:** installs the tools FluxGuard needs, and sets up Python.

Open a terminal (`Ctrl + Alt + T`) and paste this whole block:

```bash
sudo apt update && sudo apt install -y \
  clang llvm libelf-dev libpcap-dev gcc-multilib build-essential \
  linux-tools-$(uname -r) linux-headers-$(uname -r) linux-tools-common \
  m4 pkg-config iproute2 python3 python3-pip python3-venv hping3 tcpdump curl git bpftool
```

It will download a lot and take a few minutes. Then set up the project:

```bash
cd /home/samarth/fluxguard
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

> **Note:** `cd` means "go into this folder." After `source venv/bin/activate` you'll see
> `(venv)` at the start of your terminal line — that's good, it means Python is ready.
> If you close the terminal and come back later, run `cd /home/samarth/fluxguard` and
> `source venv/bin/activate` again.

**✅ What you should see:** no red "error" text at the end; `clang --version` prints a version number.

---

## Stage 1 — Run the safe tests first (no risk, catches mistakes early)

**What this does:** checks the math and settings inside FluxGuard without touching the network.
Safe to run anytime.

```bash
cd /home/samarth/fluxguard
make test
```

**✅ What you should see:** a list of test names, then a green line like **`12 passed`**
(a few may say "skipped" — that's fine).

**❌ If you see "failed":** something in the code is off — stop and send me the output.

---

## Stage 2 — Build the fake network (the client → shield → backend setup)

**What this does:** creates the 3 mini-computers and wires them together.

Open the file `FLUXGUARD_COMMANDS_samarth_phase1.txt` (in the project folder) and run its
commands. Easiest way — run the whole file at once:

```bash
cd /home/samarth/fluxguard
sudo bash FLUXGUARD_COMMANDS_samarth_phase1.txt
```

Then prepare the storage area for the maps:

```bash
sudo mount -t bpf none /sys/fs/bpf/ 2>/dev/null || true
sudo mkdir -p /sys/fs/bpf/fluxguard
```

Now test the fake network works:

```bash
sudo ip netns exec client ping -c 2 10.0.2.2
```

**✅ What you should see:** two lines saying `64 bytes from 10.0.2.2 ...` and `0% packet loss`.
That means the attacker can reach the server (through our shield). 

> `ip netns exec client ...` means "run this command as if you were the **client** computer."

---

## Stage 3 — Load FluxGuard into Linux and save its maps

**What this does:** compiles the shield program, loads it onto the shield computer's network
card, and pins its 12 maps so our tools can read them.

Compile it:

```bash
cd /home/samarth/fluxguard
make build
make verify
```

**✅ `make verify` should list lines containing `maps` and `xdp`.**

Load it onto the shield (`veth-fg-in` is the shield's incoming network card):

```bash
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/fluxguard/*
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdpgeneric obj fluxguard_kern.o sec xdp
sudo ip netns exec fluxguard ip link show veth-fg-in | grep -i xdp
```

**✅ The last line should show text containing `xdp`** — that means it loaded.

Save (pin) all 12 maps — paste this whole block:

```bash
for map in meter_map blacklist_map allowlist_map rate_map \
  meter_map_v6 blacklist_map_v6 allowlist_map_v6 rate_map_v6 \
  global_counter_map global_rate_map proto_filter_map event_ringbuf; do
  ID=$(sudo ip netns exec fluxguard bpftool map show | grep -w "$map" | head -1 | awk '{print $1}' | tr -d ':')
  [ -n "$ID" ] && sudo ip netns exec fluxguard bpftool map pin id "$ID" /sys/fs/bpf/fluxguard/"$map" \
    && echo "PIN $map" || echo "WARN missing $map"
done
ls -la /sys/fs/bpf/fluxguard/
```

**✅ What you should see:** twelve `PIN ...` lines, and the final `ls` shows 12 files.
If you see any `WARN missing`, tell me which map.

> ⚠️ **Important:** in this VM lab, load XDP with the `ip netns exec fluxguard ...` commands
> above. Do **NOT** use `make attach` here — that command is only for a real network card
> (Stage 7), not our fake network.

---

## Stage 4 — The real test: attack ourselves and watch FluxGuard block it

This is the important part. You'll need **4 terminal windows**. Open them with `Ctrl + Alt + T`.
In each new terminal, first run `cd /home/samarth/fluxguard` and `source venv/bin/activate`.

### Terminal A — start FluxGuard's brain (leave this running the whole time)

```bash
sudo python3 fluxguard_brain.py --netns fluxguard --poll-interval 0.2 \
  --cooldown-sec 30 --allowlist-refresh-sec 5 --verbose \
  --log-file /home/samarth/fluxguard/fluxguard.log
```

**✅ You should see:** `Phase 11 Brain started...` and `IPv6 support enabled...`.
Leave this window alone — watch it for messages.

### Terminal B — check normal traffic still works

```bash
sudo ip netns exec client ping -c 4 10.0.2.2
```
**✅ 4 successful pings.** Normal traffic is allowed.

### Terminal C — launch a flood attack (the main event)

```bash
sudo ip netns exec client hping3 --flood -S -p 80 10.0.2.2
```
**✅ Look at Terminal A:** within ~1 second it should print
`[KERNEL AUTO-BLOCK DETECTED] ip=10.0.1.1`. That means FluxGuard caught the attacker.
Stop the attack with `Ctrl + C` in Terminal C.

### Terminal D — prove the server was protected

Start this **before** the flood, or run the flood again while watching:
```bash
sudo ip netns exec backend tcpdump -i veth-backend -n tcp port 80
```
**✅ After the block kicks in, almost no packets reach the backend.** Stop with `Ctrl + C`.

### The rest of the checks (do these in Terminal B, C, or D)

| # | Command | ✅ What should happen |
|---|---------|----------------------|
| Allowlist | `sudo python3 fluxguard_allow.py add 10.0.1.5` then `... list` then `... del 10.0.1.5` | add shows it, list shows it, del removes it |
| Allowlist works | add `10.0.1.5`, wait 6 seconds, then `sudo ip netns exec client hping3 --flood -S -p 80 -a 10.0.1.5 10.0.2.2` | this IP is **NOT** blocked (it's trusted) |
| Persistence | flood to get a block, then `cat blocked_ips.json`, then stop brain (`Ctrl+C` in A) and start it again | on restart Terminal A says `Loaded 1 blocks from persistence checkpoint` |
| Metrics | `curl -s http://127.0.0.1:9090/metrics \| grep -E "blocked_ip\|shields\|global"` | you see counter lines |
| Shields-Up (big flood) | `sudo ip netns exec client hping3 --flood --rand-source -S -p 80 10.0.2.2` | Terminal A prints `[SHIELDS UP DETECTED]`. Stop with `Ctrl+C`. |

> `cat somefile` just prints a file's contents. `Ctrl + C` stops whatever is running in that terminal.

---

## Stage 5 — Test the web API (this is the part that was broken and got fixed)

**What this does:** starts a small web service so you can control FluxGuard over HTTP.
Keep the brain (Terminal A) running.

First create the config file:
```bash
sudo mkdir -p /etc/fluxguard /var/lib/fluxguard /var/log/fluxguard
```
Then copy the config block from `FLUXGUARD_COMMANDS_samarth_phase13.txt` (step 6) into
`/etc/fluxguard/config.json`.

Start the API in a new terminal:
```bash
cd /home/samarth/fluxguard && source venv/bin/activate
python3 fluxguard_api.py
```
Leave it running. In **another** terminal, test it:
```bash
curl -s http://127.0.0.1:8080/api/v1/health
curl -s -X POST http://127.0.0.1:8080/api/v1/allowlist -H 'Content-Type: application/json' -d '{"ip":"10.0.1.5"}'
curl -s http://127.0.0.1:8080/api/v1/allowlist
curl -s http://127.0.0.1:8080/api/v1/blocked
```
**✅ What you should see:** `/health` shows the maps as `true`; the POST replies
`{"added":"10.0.1.5"}`; the allowlist list now includes `10.0.1.5`. **If these work, the API
fix is confirmed.** Stop the API with `Ctrl + C` when done.

---

## Stage 5.5 — (Optional) run FluxGuard as an auto-starting service

**What this does:** so far you started the brain and API **by hand** in a terminal — close the
terminal and they stop. A "service" makes Linux run them in the background automatically, even
after a reboot. This is a nice-to-have that makes the project look production-ready. **You can
skip it and still finish the demo.**

> ⚠️ **Precondition:** the XDP program must already be loaded and its 12 maps pinned (Stage 3).
> The services read those maps — they do **not** load XDP themselves. So do Stage 3 first.
> Also, before starting the service, stop any brain you started by hand (`Ctrl + C` in Terminal A).

Install and start the brain service:

```bash
cd /home/samarth/fluxguard
sudo cp fluxguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fluxguard.service
sudo systemctl status fluxguard.service
```

**✅ What you should see:** `status` shows a green **`active (running)`**. Press `q` to exit the
status view.

Install and start the API service (optional):

```bash
sudo cp fluxguard-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fluxguard-api.service
sudo systemctl status fluxguard-api.service
```

Useful commands to remember:

| Command | What it does |
|---------|--------------|
| `sudo systemctl status fluxguard` | see if it's running |
| `sudo systemctl restart fluxguard` | restart it |
| `sudo systemctl stop fluxguard` | stop it |
| `journalctl -u fluxguard -f` | watch its live log messages (like Terminal A before). `Ctrl + C` to exit. |

> `enable` = start automatically on boot. `--now` = also start it right now.

**Before Stage 6 cleanup, stop the services again:**
```bash
sudo systemctl stop fluxguard-api.service fluxguard.service
sudo systemctl disable fluxguard-api.service fluxguard.service
```

---

## Stage 6 — Clean up and put it on GitHub

**What this does:** turns everything off and uploads your project.

Turn it off:
```bash
sudo ip netns exec fluxguard ip link set dev veth-fg-in xdp off 2>/dev/null || true
sudo pkill -TERM -f fluxguard_brain.py || true
sudo pkill -TERM -f fluxguard_api.py || true
make clean
```

Upload (you need a free GitHub account and an empty repo created on github.com first):
```bash
cd /home/samarth/fluxguard
git init
git add .
git status
git commit -m "FluxGuard: XDP/eBPF DDoS mitigation (phases 1-13)"
git branch -M main
git remote add origin https://github.com/<your-username>/fluxguard.git
git push -u origin main
```
**✅ What you should see:** `git status` should NOT list `fluxguard.log`, `blocked_ips.json`,
or `graphify-out/` (they're hidden on purpose). After `git push`, refresh your GitHub page —
your files and the README appear.

> The first `git push` may ask for your GitHub username and a **token** (not your password).
> If it does, create one at github.com → Settings → Developer settings → Personal access tokens.

---

## Stage 7 — (Optional, skip for now) test on a real network card

Only if you want to go beyond the fake network later. **This** is where `make attach` is used:
```bash
make build
sudo make attach IFACE=eth0 XDP_MODE=xdpdrv NETNS=fluxguard
```
Skip this for your resume demo — the fake-network test (Stages 1–5) is enough to prove it works.

---

## ❌ If it breaks — quick help

| Problem | Likely fix |
|---------|-----------|
| `command not found` | You skipped Stage 0 installs, or forgot `source venv/bin/activate`. |
| `Permission denied` / `Operation not permitted` | You forgot `sudo` at the front. |
| `sudo` asks for a password and nothing appears | Normal — type your password blindly and press Enter. |
| Stage 3 shows `WARN missing <map>` | The program didn't load right — tell me which map is missing. |
| Terminal A shows no `AUTO-BLOCK` during a flood | Make sure the flood (Terminal C) is running and the brain (Terminal A) is still up. |
| `ping` fails in Stage 2 | The fake network didn't build — re-run Stage 2 from the top. |
| Anything red you don't understand | Copy the whole message and send it to me. |

**Golden rule:** if a stage fails, stop there. Don't continue — the broken stage tells us exactly
what to fix. Send me the exact red text and which stage you were on.

---

*Note: this plan was prepared on a Windows PC, so the Python parts were checked there, but the
Linux-only parts (loading XDP, the network attacks) can only be truly confirmed here on the VM.
That's what this whole guide is for.*
