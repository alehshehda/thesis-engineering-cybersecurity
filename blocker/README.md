# Blocker Module - SSH Brute-Force Firewall Automation

## Overview
Independent module for automatic firewall blocking via OPNsense API based on ML-generated SSH brute-force alerts.

## Installation

### 1. Create Blocker Directory
```bash
mkdir -p /root/Thesis/blocker
cd /root/Thesis/blocker
```

### 2. Copy Files
Copy all generated files to `/root/Thesis/blocker/`:
- blocker.py
- blocker_config.json
- blocker_setup.sh
- requirements.txt
- whitelist.json

### 3. Make Setup Script Executable
```bash
chmod +x blocker_setup.sh
```

### 4. Run Setup
```bash
sudo bash blocker_setup.sh
```

### 5. Configure OPNsense Credentials
Edit `blocker_config.json` and set:
- opnsense.api_url: https://192.168.20.1 (or your OPNsense IP)
- opnsense.api_key: Your API key
- opnsense.api_secret: Your API secret

### 6. Start Blocker Service
```bash
cd /root/Thesis/blocker
source venv/bin/activate
python3 blocker.py
```

## Directory Structure
```
/root/Thesis/blocker/
├── blocker.py                    Main service script
├── blocker_config.json           Configuration file
├── blocker_setup.sh              Setup script
├── requirements.txt              Python dependencies
├── whitelist.json                Whitelisted IPs
├── state/
│   ├── blocked_ips.json         Current active blocks
│   └── block_history_YYYYMM.json Monthly archives
├── queue/
│   └── pending_blocks.json      Failed API calls
├── logs/
│   └── blocker_YYYYMMDD.log     Rotating logs
├── stats/
│   └── blocker_stats.json       Live statistics
└── venv/                         Python virtual environment
```

## Configuration

### Tier Determination (Average Confidence)
- 70-75%: 30 minute block
- 75-85%: 8 hour block
- 85-95%: 24 hour block
- 95-100%: Permanent block (manual removal only)

### Key Settings
- kill_connections_before_block: true (terminates active SSH sessions)
- auto_create_aliases: true (creates aliases if missing)
- auto_reorder_rules: true (ensures rule at top position)
- unblock_check_interval_seconds: 60 (auto-unblock check frequency)
- whitelist_reload_interval_seconds: 60 (whitelist reload frequency)
- history_retention_days: 30 (keeps 30 days of blocking history)

## Operation

### Workflow
1. ML module detects SSH brute-force attack, generates alert JSON
2. Blocker monitors /root/Thesis/ml/alerts/ directory
3. On new alert:
   - Parse attacker IP and confidence score
   - Validate against whitelist
   - Check if already blocked
   - Determine tier from confidence
   - Kill active SSH connections via OPNsense API
   - Add IP to appropriate alias
   - Save to state file
   - Move alert to /root/Thesis/ml/alerts/processed/

### Auto-Unblock
- Background thread checks every 60 seconds
- Temporary blocks (30min, 8h, 24h) auto-expire
- Permanent blocks require manual removal
- Expired blocks archived to monthly history

### Whitelist Protection
- Automatically reload every 60 seconds
- Prevents blocking internal IPs
- Supports CIDR notation (e.g., 192.168.10.0/24)

### Retry Queue
- Failed API calls automatically queued
- Retry every 30 seconds
- Max 3 attempts before giving up
- Failed IPs logged for manual investigation

## Logs

Location: `/root/Thesis/blocker/logs/blocker_YYYYMMDD.log`

Example log entries:
```
2025-11-02 18:35:23 - blocker - INFO - New alert detected: alert_192_168_30_102_20251029_111525.json
2025-11-02 18:35:23 - blocker - INFO - Processing IP: 192.168.30.102
2025-11-02 18:35:23 - blocker - INFO - Average confidence: 76.82%
2025-11-02 18:35:23 - blocker - INFO - Tier determined: 8hours (75% <= 76.82% < 85%)
2025-11-02 18:35:24 - blocker - INFO - Killing SSH connections from 192.168.30.102:22
2025-11-02 18:35:25 - blocker - INFO - BLOCKED: 192.168.30.102 -> 8hours (confidence: 76.82%, unblock: 2025-11-03 02:35:25)
2025-11-03 02:35:26 - blocker - INFO - UNBLOCKED: 192.168.30.102 (8hours expired)
```

## Statistics

Location: `/root/Thesis/blocker/stats/blocker_stats.json`

Tracks:
- Total blocks and current active blocks
- Breakdown by tier (30min, 8h, 24h, permanent)
- Total unblocks
- Skipped blocks (whitelisted, already blocked, below threshold)
- API call success/failure rates

## State Files

### blocked_ips.json
Current active blocks with:
- Block and unblock timestamps
- Tier and confidence score
- Number of flows detected
- Alert file reference

### block_history_YYYYMM.json
Monthly archives of all blocks with full details for audit trail.

### pending_blocks.json
Failed API calls queued for retry with:
- Number of retry attempts
- Next retry time
- Original alert data

## OPNsense Setup Requirements

### Prerequisites
- OPNsense firewall at 192.168.20.1 (or configured IP)
- API key and secret generated
- LAN interface accessible

### Manual Setup (if auto-create disabled)
1. Create 4 aliases:
   - ssh_block_30min
   - ssh_block_8hours
   - ssh_block_24hours
   - ssh_block_permanent

2. Create firewall rule:
   - Interface: LAN
   - Type: block
   - Protocol: TCP
   - Destination port: 22
   - Source: EXCLUDE (ssh_block_30min OR ssh_block_8hours OR ssh_block_24hours OR ssh_block_permanent)
   - Description: "SSH Brute-Force Block All Tiers (ML-managed)"
   - Position: Top of ruleset

## Troubleshooting

### Blocker won't start
- Check Python version: `python3 --version` (3.6+)
- Check config: `cat blocker_config.json | python3 -m json.tool`
- Check logs: `tail -f logs/blocker_*.log`

### IPs not being blocked
- Verify OPNsense API credentials
- Check OPNsense connectivity: `curl -k https://192.168.20.1/api/core/system/status`
- Review logs for API errors
- Ensure alerts are being generated: `ls /root/Thesis/ml/alerts/`

### Whitelist not working
- Check format: `cat whitelist.json | python3 -m json.tool`
- Verify IP addresses are valid

### High API failure rate
- Check OPNsense system load
- Increase timeout in config if needed
- Check network connectivity

## Performance Considerations

- Each block/unblock requires 2-3 OPNsense API calls
- Whitelist reloaded every 60 seconds
- Auto-unblock checks every 60 seconds
- Retry queue checked every 30 seconds
- Alert processing has 2-second delay for file I/O safety

## Security Notes

- API credentials stored in plaintext (limit file permissions)
- Consider using environment variables for credentials in production
- Restrict file permissions: `chmod 600 blocker_config.json`
- Run as non-root if possible
- Monitor API logs for unusual activity

## Integration with ML Module

Blocker reads alerts generated by ML module:
- Input: `/root/Thesis/ml/alerts/*.json`
- Output: Processed alerts moved to `/root/Thesis/ml/alerts/processed/`
- No changes needed to ML module
- Independent operation and failure modes

## Support & Monitoring

### Health Check
```bash
tail -n 50 /root/Thesis/blocker/logs/blocker_*.log | grep -E "BLOCKED|UNBLOCKED|ERROR"
```

### Current Status
```bash
cat /root/Thesis/blocker/stats/blocker_stats.json | python3 -m json.tool
```

### Active Blocks
```bash
cat /root/Thesis/blocker/state/blocked_ips.json | python3 -m json.tool
```

### Failed Blocks
```bash
cat /root/Thesis/blocker/queue/pending_blocks.json | python3 -m json.tool
```

## Version
- 1.0
- Release Date: 2025-11-02
- Python: 3.6+
- Dependencies: requests, watchdog, python-dateutil
