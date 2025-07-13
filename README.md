# IronGolem Enhanced - Anti-DDoS for Minecraft

Real-time DDoS protection for Minecraft servers. Automatically blocks attacks and keeps your server online.

## What it does

- Monitors connections and blocks suspicious IPs
- Rate limits connections per IP
- Protects against SYN floods and connection spam
- Sends Discord alerts when stuff happens
- Auto-unbans IPs after set time
- Blocks known bad IP ranges
- Optional country blocking

## Requirements

- Linux server with root access
- Python 3.6+
- iptables

Install dependencies:
```bash
pip3 install requests colorama psutil
```

## Setup

1. Download the script
2. Edit the CONFIG section at the top:
   - Set your Minecraft port
   - Add your Discord webhook URL
   - Configure rate limits
   - Add trusted IPs that shouldn't be blocked
3. Run it: `sudo python3 main.py`

## Key Settings

```python
CONFIG = {
    "minecraft_port": 25565,
    "trusted_ips": ["127.0.0.1", "your.admin.ip"],
    "discord_webhook_url": "your_webhook_here",
    "auto_unban_time": 3600,  # 1 hour
    "rate_limits": {
        "mc_connlimit": 5,        # max connections per IP
        "mc_flood_hitcount": 10,  # connections before blocking
        "global_pps_limit": 1000  # packets per second limit
    }
}
```

## Usage

Start protection:
```bash
sudo python3 main.py
```

Stop with Ctrl+C - it'll clean up the firewall rules automatically.

The script runs continuously, monitoring your server and blocking threats in real-time. Check your Discord channel for alerts.

## What gets blocked

- IPs with too many connections
- SYN flood attacks
- Private/bogon IP ranges
- UDP packets to Minecraft port
- Countries you specify (optional)
- IPs that trip the rate limits

## Important notes

- Make sure your IP is in the trusted_ips list before running
- Test your SSH access after setup
- The script needs root to modify iptables
- Blocked IPs auto-unban after 1 hour by default

## Need help?

DM me @j0rrdnn on Discord if you run into issues.
