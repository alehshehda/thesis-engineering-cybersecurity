#!/usr/bin/env python3

"""
SSH Brute-Force Blocker Module
Automatic blocking via OPNsense aliases - alias management only
Fixed: Appends IPs to aliases + Timer reset on repeated attempts
"""

import os
import sys
import json
import time
import logging
import threading
import requests
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class OPNsenseAPI:
    """OPNsense API client for alias management"""
    
    def __init__(self, api_url, api_key, api_secret, verify_ssl=False, timeout=10):
        self.api_url = api_url
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.auth = (api_key, api_secret)
        self.logger = logging.getLogger(__name__)
    
    def _request(self, method, endpoint, data=None):
        """Make API request to OPNsense"""
        url = f"{self.api_url}/api{endpoint}"
        try:
            if method == "GET":
                response = self.session.get(url, timeout=self.timeout)
            elif method == "POST":
                response = self.session.post(url, json=data, timeout=self.timeout)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            return response.json() if response.text else {}
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {method} {endpoint} - {e}")
            return None
    
    def search_aliases(self):
        """Search/list all aliases"""
        data = {"current": 1, "rowCount": 1000, "sort": {}, "searchPhrase": ""}
        return self._request("POST", "/firewall/alias/searchItem", data)
    
    def get_alias(self, uuid):
        """Get specific alias by UUID"""
        return self._request("GET", f"/firewall/alias/getItem/{uuid}")
    
    def create_alias(self, name, alias_type="host", content="", enabled=1, description=""):
        """Create new alias"""
        data = {
            "alias": {
                "name": name,
                "type": alias_type,
                "content": content,
                "enabled": enabled,
                "description": description
            }
        }
        result = self._request("POST", "/firewall/alias/addItem", data)
        if result and "uuid" in result:
            self.logger.info(f"Created alias: {name} (UUID: {result['uuid']})")
        return result
    
    def update_alias(self, uuid, content, enabled=1, description=""):
        """Update alias with new content (APPENDS, not overwrites)"""
        data = {
            "alias": {
                "uuid": uuid,
                "content": content,
                "enabled": enabled,
                "description": description
            }
        }
        return self._request("POST", f"/firewall/alias/setItem/{uuid}", data)
    
    def reconfigure_aliases(self):
        """Apply alias changes"""
        return self._request("POST", "/firewall/alias/reconfigure")


class BlockerService:
    """Main blocker service - alias management with timer reset on repeated attempts"""
    
    def __init__(self, config_path="/root/Thesis/blocker/blocker_config.json"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialize paths
        self.state_dir = Path(self.config['paths']['state_dir'])
        self.queue_dir = Path(self.config['paths']['queue_dir'])
        self.stats_dir = Path(self.config['paths']['stats_dir'])
        self.alerts_dir = Path(self.config['paths']['alerts_watch'])
        self.alerts_processed_dir = Path(self.config['paths']['alerts_processed'])
        self.whitelist_path = Path(self.config['paths']['whitelist'])
        
        # Create directories
        for path in [self.state_dir, self.queue_dir, self.stats_dir, self.alerts_processed_dir]:
            path.mkdir(parents=True, exist_ok=True)
        
        # Initialize OPNsense API
        self.opnsense = OPNsenseAPI(
            self.config['opnsense']['api_url'],
            self.config['opnsense']['api_key'],
            self.config['opnsense']['api_secret'],
            verify_ssl=self.config['opnsense']['verify_ssl'],
            timeout=self.config['opnsense']['timeout']
        )
        
        # State tracking
        self.blocked_ips = self._load_state()
        self.whitelist = self._load_whitelist()
        self.is_running = False
        
        # File watchers
        self.observer = None
        self.last_whitelist_reload = datetime.now()
        
        self.logger.info("BlockerService initialized")
    
    def _load_config(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            return config
        except Exception as e:
            print(f"ERROR: Failed to load config: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Configure logging with rotation"""
        log_dir = Path(self.config['paths']['logs_dir'])
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"blocker_{datetime.now().strftime('%Y%m%d')}.log"
        
        formatter = logging.Formatter(self.config['logging']['format'])
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=self.config['logging']['max_bytes'],
            backupCount=self.config['logging']['backup_count']
        )
        file_handler.setFormatter(formatter)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        
        logging.basicConfig(
            level=getattr(logging, self.config['logging']['level']),
            handlers=[file_handler, console_handler]
        )
    
    def _load_state(self):
        """Load blocked IPs state from file"""
        state_file = self.state_dir / "blocked_ips.json"
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.warning(f"Failed to load state: {e}")
        return {}
    
    def _save_state(self):
        """Save blocked IPs state to file"""
        try:
            state_file = self.state_dir / "blocked_ips.json"
            with open(state_file, 'w') as f:
                json.dump(self.blocked_ips, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save state: {e}")
    
    def _load_whitelist(self):
        """Load whitelist from JSON file"""
        if self.whitelist_path.exists():
            try:
                with open(self.whitelist_path, 'r') as f:
                    return set(json.load(f).keys())
            except Exception as e:
                self.logger.warning(f"Failed to load whitelist: {e}")
        return set()
    
    def _is_whitelisted(self, ip):
        """Check if IP or network is whitelisted"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for whitelist_entry in self.whitelist:
                try:
                    if "/" in whitelist_entry:
                        network = ipaddress.ip_network(whitelist_entry)
                        if ip_obj in network:
                            return True
                    elif ip == whitelist_entry:
                        return True
                except:
                    pass
            return False
        except:
            return False
    
    def _determine_tier(self, confidence):
        """Determine blocking tier based on average confidence"""
        thresholds = self.config['blocking']['thresholds']
        
        if confidence < 0.70:
            return None
        elif confidence < thresholds['8hours'][0]:
            return "30min"
        elif confidence < thresholds['24hours'][0]:
            return "8hours"
        elif confidence < thresholds['permanent'][0]:
            return "24hours"
        else:
            return "permanent"
    
    def _calculate_unblock_time(self, tier):
        """Calculate unblock time based on tier"""
        now = datetime.now()
        if tier == "30min":
            return (now + timedelta(minutes=30)).isoformat()
        elif tier == "8hours":
            return (now + timedelta(hours=8)).isoformat()
        elif tier == "24hours":
            return (now + timedelta(hours=24)).isoformat()
        else:
            return None
    
    def _add_to_queue(self, ip, tier, alias, confidence, flows, alert_file):
        """Add failed block to retry queue"""
        queue_file = self.queue_dir / "pending_blocks.json"
        
        try:
            queue = {}
            if queue_file.exists():
                with open(queue_file, 'r') as f:
                    queue = json.load(f)
            
            queue[ip] = {
                "tier": tier,
                "alias": alias,
                "confidence": confidence,
                "flows": flows,
                "alert_file": alert_file,
                "blocked_at": datetime.now().isoformat(),
                "attempts": 1,
                "last_attempt": datetime.now().isoformat(),
                "next_retry": (datetime.now() + timedelta(seconds=self.config['retry']['retry_interval_seconds'])).isoformat()
            }
            
            with open(queue_file, 'w') as f:
                json.dump(queue, f, indent=2)
            
            self.logger.warning(f"Added {ip} to retry queue")
        except Exception as e:
            self.logger.error(f"Failed to add to queue: {e}")
    
    def _block_ip(self, ip, tier, alert_data):
        """Block IP via OPNsense alias - APPENDS IP and RESETS timer on repeated attempts"""
        try:
            alias_name = self.config['opnsense']['aliases'][tier]
            confidence = alert_data['confidence']['average']
            total_flows = alert_data['total_flows']
            alert_file = alert_data.get('filename', 'unknown')

            self.logger.info(f"Blocking {ip} tier {tier} (confidence: {confidence * 100:.2f}%)")

            # Check if IP is ALREADY blocked
            if ip in self.blocked_ips:
                existing_block = self.blocked_ips[ip]
                old_unblock_time = existing_block.get('unblock_at')
                attempt_count = existing_block.get('attempt_count', 1)
                
                # RESET TIMER - keep blocking but extend the time!
                new_unblock_time = self._calculate_unblock_time(tier)
                
                self.logger.info(f"IP {ip} already blocked, RESETTING timer (attempt #{attempt_count + 1})")
                self.logger.info(f"  Old unblock time: {old_unblock_time}")
                self.logger.info(f"  New unblock time: {new_unblock_time}")
                self.logger.info(f"  Attacker still attempting - timer reset")
                
                # Update the unblock time and attempt count
                self.blocked_ips[ip]['unblock_at'] = new_unblock_time
                self.blocked_ips[ip]['last_attempt'] = datetime.now().isoformat()
                self.blocked_ips[ip]['attempt_count'] = attempt_count + 1
                self._save_state()
                
                self._update_stats("block_reset", tier)
                return True
            
            # NEW BLOCK - search for alias and append IP
            
            # Search for alias
            aliases_result = self.opnsense.search_aliases()
            if not aliases_result:
                self.logger.error(f"Failed to search aliases")
                self._add_to_queue(ip, tier, alias_name, confidence, total_flows, alert_file)
                return False

            alias_uuid = None
            alias_content = ""
            if 'rows' in aliases_result:
                for alias in aliases_result['rows']:
                    if alias.get('name') == alias_name:
                        alias_uuid = alias.get('uuid')
                        alias_content = alias.get('content', '')
                        break

            if not alias_uuid:
                self.logger.error(f"Alias {alias_name} not found")
                self._add_to_queue(ip, tier, alias_name, confidence, total_flows, alert_file)
                return False

            # CHECK IF IP ALREADY IN ALIAS
            if alias_content:
                ip_list = [line.strip() for line in alias_content.split('\n') if line.strip()]
                if ip in ip_list:
                    self.logger.info(f"IP {ip} already in alias {alias_name}, skipping add")
                else:
                    ip_list.append(ip)
                    new_content = '\n'.join(ip_list)
                    self.logger.debug(f"Appending {ip} to alias {alias_name}. Total IPs now: {len(ip_list)}")
            else:
                ip_list = [ip]
                new_content = ip

            # Update alias with FULL content (existing + new)
            description = f"Blocked by ML: {confidence * 100:.2f}% confidence, {total_flows} flows"
            result = self.opnsense.update_alias(alias_uuid, new_content, enabled=1, description=description)

            if not result:
                self.logger.error(f"Failed to update alias {alias_name}")
                self._add_to_queue(ip, tier, alias_name, confidence, total_flows, alert_file)
                return False

            # Reconfigure aliases
            if not self.opnsense.reconfigure_aliases():
                self.logger.error(f"Failed to reconfigure aliases")
                self._add_to_queue(ip, tier, alias_name, confidence, total_flows, alert_file)
                return False

            # Save to blocked_ips state
            unblock_at = self._calculate_unblock_time(tier)
            self.blocked_ips[ip] = {
                "blocked_at": datetime.now().isoformat(),
                "unblock_at": unblock_at,
                "tier": tier,
                "alias": alias_name,
                "confidence_avg": confidence,
                "total_flows": total_flows,
                "alert_id": alert_data.get('alert_id', 'unknown'),
                "alert_file": alert_file,
                "status": "active",
                "attempt_count": 1
            }
            self._save_state()

            # Update statistics
            self._update_stats("block", tier)

            unblock_time = unblock_at if unblock_at else "never (manual removal)"
            self.logger.info(f"BLOCKED: {ip} -> {tier} (confidence: {confidence * 100:.2f}%, unblock: {unblock_time}, total in alias: {len(ip_list)})")
            return True

        except Exception as e:
            self.logger.error(f"Failed to block {ip}: {e}")
            return False
    
    def _update_stats(self, action, tier=None):
        """Update statistics file with persistence tracking"""
        try:
            stats_file = self.stats_dir / "blocker_stats.json"
            
            stats = {}
            if stats_file.exists():
                with open(stats_file, 'r') as f:
                    stats = json.load(f)
            
            if not stats:
                stats = {
                    "service_start_time": datetime.now().isoformat(),
                    "total_blocks": 0,
                    "block_timer_resets": 0,
                    "currently_blocked": 0,
                    "tier_breakdown": {"30min": 0, "8hours": 0, "24hours": 0, "permanent": 0},
                    "persistent_attackers": {},
                    "total_unblocks": 0,
                    "failed_blocks": 0,
                    "skipped_blocks": {"whitelisted": 0, "already_blocked": 0, "below_threshold": 0}
                }
            
            if action == "block":
                stats["total_blocks"] = stats.get("total_blocks", 0) + 1
                stats["currently_blocked"] = len(self.blocked_ips)
                if tier:
                    stats["tier_breakdown"][tier] = stats["tier_breakdown"].get(tier, 0) + 1
            elif action == "block_reset":
                stats["block_timer_resets"] = stats.get("block_timer_resets", 0) + 1
                stats["currently_blocked"] = len(self.blocked_ips)
            elif action == "unblock":
                stats["total_unblocks"] = stats.get("total_unblocks", 0) + 1
                stats["currently_blocked"] = len(self.blocked_ips)
                if tier:
                    stats["tier_breakdown"][tier] = max(0, stats["tier_breakdown"].get(tier, 0) - 1)
            elif action == "skip_whitelist":
                stats["skipped_blocks"]["whitelisted"] = stats["skipped_blocks"].get("whitelisted", 0) + 1
            elif action == "skip_already_blocked":
                stats["skipped_blocks"]["already_blocked"] = stats["skipped_blocks"].get("already_blocked", 0) + 1
            elif action == "skip_threshold":
                stats["skipped_blocks"]["below_threshold"] = stats["skipped_blocks"].get("below_threshold", 0) + 1
            
            stats["uptime_seconds"] = int((datetime.now() - datetime.fromisoformat(stats.get("service_start_time", datetime.now().isoformat()))).total_seconds())
            
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to update stats: {e}")
    
    def _process_alert(self, alert_path):
        """Process an alert file"""
        try:
            with open(alert_path, 'r') as f:
                alert = json.load(f)
            
            attacker_ip = alert.get('attacker_ip')
            confidence_avg = alert.get('confidence', {}).get('average')
            
            if not attacker_ip or confidence_avg is None:
                self.logger.warning(f"Invalid alert format: {alert_path.name}")
                self._move_alert_to_processed(alert_path)
                return
            
            if confidence_avg < 0.70:
                self.logger.info(f"Alert below threshold: {attacker_ip} (confidence: {confidence_avg*100:.2f}%)")
                self._update_stats("skip_threshold")
                self._move_alert_to_processed(alert_path)
                return
            
            if self._is_whitelisted(attacker_ip):
                self.logger.info(f"IP whitelisted: {attacker_ip}")
                self._update_stats("skip_whitelist")
                self._move_alert_to_processed(alert_path)
                return
            
            tier = self._determine_tier(confidence_avg)
            if not tier:
                self.logger.warning(f"Could not determine tier for {attacker_ip} (confidence: {confidence_avg})")
                self._move_alert_to_processed(alert_path)
                return
            
            alert['filename'] = alert_path.name
            
            if self._block_ip(attacker_ip, tier, alert):
                self._move_alert_to_processed(alert_path)
            else:
                self.logger.error(f"Failed to block {attacker_ip}")
        
        except Exception as e:
            self.logger.error(f"Error processing alert {alert_path.name}: {e}")
    
    def _move_alert_to_processed(self, alert_path):
        """Move processed alert to processed directory"""
        try:
            processed_path = self.alerts_processed_dir / alert_path.name
            alert_path.rename(processed_path)
            self.logger.debug(f"Moved alert to processed: {alert_path.name}")
        except Exception as e:
            self.logger.error(f"Failed to move alert to processed: {e}")
    
    def _check_unblocks(self):
        """Check for expired blocks and unblock"""
        try:
            now = datetime.now()
            expired_ips = []
            
            for ip, info in self.blocked_ips.items():
                if info['tier'] == 'permanent':
                    continue
                
                unblock_at = info.get('unblock_at')
                if unblock_at and datetime.fromisoformat(unblock_at) <= now:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                self._unblock_ip(ip)
        
        except Exception as e:
            self.logger.error(f"Error checking unblocks: {e}")
    
    def _unblock_ip(self, ip):
        """Remove IP from blocked list"""
        try:
            if ip not in self.blocked_ips:
                return
            
            info = self.blocked_ips[ip]
            tier = info['tier']
            alias_name = info['alias']
            attempt_count = info.get('attempt_count', 1)
            
            self.logger.info(f"Unblocking {ip} (tier: {tier}, attempts: {attempt_count})")
            
            # Search for alias
            aliases_result = self.opnsense.search_aliases()
            if not aliases_result or 'rows' not in aliases_result:
                self.logger.error(f"Failed to search aliases for unblock")
                return False
            
            alias_uuid = None
            alias_content = ""
            for alias in aliases_result['rows']:
                if alias.get('name') == alias_name:
                    alias_uuid = alias.get('uuid')
                    alias_content = alias.get('content', '')
                    break
            
            if not alias_uuid:
                self.logger.error(f"Alias {alias_name} not found for unblock")
                return False
            
            # Remove IP from alias content (split by newline, filter out the IP)
            if alias_content:
                ip_list = [line.strip() for line in alias_content.split('\n') if line.strip() and line.strip() != ip]
                new_content = '\n'.join(ip_list)
            else:
                new_content = ""
            
            self.logger.debug(f"Removing {ip} from alias {alias_name}. New content: {new_content}")
            
            result = self.opnsense.update_alias(alias_uuid, new_content, enabled=1)
            if not result:
                self.logger.error(f"Failed to remove {ip} from alias")
                return False
            
            # Reconfigure
            if not self.opnsense.reconfigure_aliases():
                self.logger.error(f"Failed to reconfigure aliases")
                return False
            
            # Archive to history
            self._archive_to_history(ip, info)
            
            # Remove from active blocks
            del self.blocked_ips[ip]
            self._save_state()
            
            # Update stats
            self._update_stats("unblock", tier)
            
            self.logger.info(f"UNBLOCKED: {ip} ({tier} expired after {attempt_count} attempts)")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to unblock {ip}: {e}")
            return False
    
    def _archive_to_history(self, ip, info):
        """Archive blocked IP to history file"""
        try:
            month = datetime.now().strftime("%Y%m")
            history_file = self.state_dir / f"block_history_{month}.json"
            
            history = {}
            if history_file.exists():
                with open(history_file, 'r') as f:
                    history = json.load(f)
            
            if ip not in history:
                history[ip] = []
            
            history[ip].append({
                "blocked_at": info['blocked_at'],
                "unblocked_at": datetime.now().isoformat(),
                "tier": info['tier'],
                "confidence_avg": info['confidence_avg'],
                "total_flows": info['total_flows'],
                "attempts": info.get('attempt_count', 1)
            })
            
            with open(history_file, 'w') as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to archive to history: {e}")
    
    def _process_retry_queue(self):
        """Process retry queue for failed blocks"""
        try:
            queue_file = self.queue_dir / "pending_blocks.json"
            if not queue_file.exists():
                return
            
            with open(queue_file, 'r') as f:
                queue = json.load(f)
            
            now = datetime.now()
            retry_items = {ip: info for ip, info in queue.items() 
                          if datetime.fromisoformat(info['next_retry']) <= now}
            
            for ip, info in retry_items.items():
                attempts = info.get('attempts', 0)
                
                if attempts >= self.config['retry']['max_attempts']:
                    self.logger.error(f"Max retries exceeded for {ip}, giving up")
                    del queue[ip]
                    continue
                
                self.logger.info(f"Retrying block for {ip} (attempt {attempts + 1}/{self.config['retry']['max_attempts']})")
                
                alert_data = {
                    'attacker_ip': ip,
                    'confidence': {'average': info['confidence']},
                    'total_flows': info['flows'],
                    'alert_id': 'retry_queue',
                    'filename': info['alert_file']
                }
                
                if self._block_ip(ip, info['tier'], alert_data):
                    del queue[ip]
                else:
                    queue[ip]['attempts'] = attempts + 1
                    queue[ip]['last_attempt'] = datetime.now().isoformat()
                    queue[ip]['next_retry'] = (now + timedelta(seconds=self.config['retry']['retry_interval_seconds'])).isoformat()
            
            with open(queue_file, 'w') as f:
                json.dump(queue, f, indent=2)
        
        except Exception as e:
            self.logger.error(f"Error processing retry queue: {e}")
    
    def _reload_whitelist(self):
        """Reload whitelist if changed"""
        try:
            now = datetime.now()
            if (now - self.last_whitelist_reload).total_seconds() < self.config['whitelist_reload_interval_seconds']:
                return
            
            new_whitelist = self._load_whitelist()
            if new_whitelist != self.whitelist:
                self.whitelist = new_whitelist
                self.logger.info(f"Whitelist reloaded: {len(self.whitelist)} entries")
            
            self.last_whitelist_reload = now
        except Exception as e:
            self.logger.error(f"Failed to reload whitelist: {e}")
    
    def _initialize_opnsense(self):
        """Initialize OPNsense - create aliases if needed"""
        try:
            self.logger.info("Initializing OPNsense aliases")
            
            # Check/create aliases
            aliases_result = self.opnsense.search_aliases()
            if not aliases_result:
                self.logger.error("Failed to search aliases from OPNsense")
                return False
            
            existing_alias_names = {}
            if 'rows' in aliases_result:
                for alias in aliases_result['rows']:
                    existing_alias_names[alias.get('name')] = alias.get('uuid')
            
            for tier, alias_name in self.config['opnsense']['aliases'].items():
                if alias_name not in existing_alias_names:
                    self.logger.info(f"Creating alias: {alias_name}")
                    result = self.opnsense.create_alias(alias_name, alias_type="host", content="", enabled=1)
                    if not result:
                        self.logger.error(f"Failed to create alias: {alias_name}")
                        return False
                else:
                    self.logger.info(f"Alias exists: {alias_name}")
            
            self.opnsense.reconfigure_aliases()
            self.logger.info("OPNsense aliases ready")
            
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to initialize OPNsense: {e}")
            return False
    
    def start(self):
        """Start blocker service"""
        try:
            self.logger.info("================================================================")
            self.logger.info("Starting Blocker Service")
            self.logger.info("================================================================")
            
            # Initialize OPNsense
            if not self._initialize_opnsense():
                self.logger.error("OPNsense initialization failed")
                return
            
            # Start file watcher
            self.observer = Observer()
            handler = AlertHandler(self)
            self.observer.schedule(handler, str(self.alerts_dir), recursive=False)
            self.observer.start()
            self.logger.info(f"Watching for alerts in: {self.alerts_dir}")
            
            # Start background threads
            unblock_thread = threading.Thread(target=self._unblock_loop, daemon=True)
            unblock_thread.start()
            self.logger.info("Auto-unblock thread started")
            
            whitelist_thread = threading.Thread(target=self._whitelist_loop, daemon=True)
            whitelist_thread.start()
            self.logger.info("Whitelist reload thread started")
            
            retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
            retry_thread.start()
            self.logger.info("Retry queue thread started")
            
            self.is_running = True
            self.logger.info("================================================================")
            self.logger.info("Blocker Service Started Successfully")
            self.logger.info("================================================================")
            self.logger.info("Ready to process alerts from /root/Thesis/ml/alerts/")
            
            # Keep service running
            try:
                while self.is_running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Received keyboard interrupt")
                self.stop()
        
        except Exception as e:
            self.logger.error(f"Error starting service: {e}")
            self.stop()
    
    def _unblock_loop(self):
        """Background loop for auto-unblocking"""
        while self.is_running:
            try:
                self._check_unblocks()
            except Exception as e:
                self.logger.error(f"Error in unblock loop: {e}")
            time.sleep(self.config['blocking']['unblock_check_interval_seconds'])
    
    def _whitelist_loop(self):
        """Background loop for whitelist reload"""
        while self.is_running:
            try:
                self._reload_whitelist()
            except Exception as e:
                self.logger.error(f"Error in whitelist loop: {e}")
            time.sleep(self.config['whitelist_reload_interval_seconds'])
    
    def _retry_loop(self):
        """Background loop for retry queue"""
        while self.is_running:
            try:
                if self.config['retry']['queue_enabled']:
                    self._process_retry_queue()
            except Exception as e:
                self.logger.error(f"Error in retry loop: {e}")
            time.sleep(self.config['retry']['retry_interval_seconds'])
    
    def stop(self):
        """Stop blocker service"""
        self.logger.info("================================================================")
        self.logger.info("Stopping Blocker Service")
        self.logger.info("================================================================")
        
        self.is_running = False
        
        if self.observer:
            self.observer.stop()
            self.observer.join()
        
        self.logger.info("Blocker Service Stopped")


class AlertHandler(FileSystemEventHandler):
    """Watches for new alert files"""
    
    def __init__(self, blocker_service):
        self.blocker = blocker_service
        self.logger = logging.getLogger(__name__)
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith('.json'):
            self.logger.info(f"New alert detected: {Path(event.src_path).name}")
            time.sleep(2)
            self.blocker._process_alert(Path(event.src_path))


def main():
    """Main entry point"""
    blocker = BlockerService()
    blocker.start()


if __name__ == '__main__':
    main()
