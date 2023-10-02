import argparse
import sys
from dataclasses import dataclass
from importlib.metadata import version
from typing import List

from loguru import logger as LOGGER

from utils import *
from scanner import WindowsWiFiScanner, IwWiFiScanner, IwlistWiFiScanner, NetworkManagerWiFiScanner, ScannerBase
from scanner import CONSTANTS


# == Adapter Object ==========================================================================================================   
@dataclass 
class AdapterInfo:
    name: str
    desc: str = ''
    mac: str = ''
    connected: bool = False
    SSID: str = 'Not Associated'
    BSSID: str = ''
    radio_type: str = ''
    Authentication: str = ''
    cipher: str = ''
    channel: int = -1
    receive_rate: float = -1.0
    transmit_rate: float = -1.0
    signal: int = -1

    def __post_init__(self):
        if running_on_windows():
            if not self._get_windows_adapter():
                raise NameError(f'Unable to identify adapter "{self.name}"')
        elif running_on_linux():
            if not self._get_linux_adapter():
                raise NameError(f'Unable to identify adapter "{self.name}"')
        else:
            raise NameError(f'No adapter exists named "{self.name}"')
        
    def _get_linux_adapter(self) -> bool:
        # iw wlan0 info = channel, mhz, mac
        iwconfig_output, _ = ScannerBase._execute_process('iwconfig', show_feedback=False)
        adapter_found = False
        for line in iwconfig_output:
            line = line.strip()
            if 'ESSID' in line:
                if adapter_found:
                    # done, bail
                    break
                adapter_found = True
                self.SSID = line.split('ESSID:')[1].strip()
                continue
            if "Frequency:" in line:
                token = line.split('Frequency:')[1].strip()
                if token.startswith('2'):
                    self.radio_type = "2.4 GHz"
                elif token.startswith('5'):
                    self.radio_type = '5 GHz'
            if "Access Point:" in line:
                self.BSSID = line.split('Access Point:')[1].strip()
            if "Bit Rate=" in line:
                self.receive_rate = line.split('Bit Rate=')[1].split()[0]
                self.transmit_rate = self.receive_rate
            if "Link Quality=" in line:
                txt_sig = line.split('=')[1].split()[0]
                signals = txt_sig.split('/')
                self.signal = int(int(signals[0]) / int(signals[1]) * 100)
            # self.Authentication
            # self.channel
            # self.cipher
            # self.connected
            # self.desc
            # self.mac
            # self.radio_type

        return adapter_found
    
    def _get_windows_adapter(self) -> bool:
        netsh_output, _ = ScannerBase._execute_process(f'netsh wlan show interfaces', show_feedback=False)
        adapter_found = False
        for line in netsh_output:
            line = line.strip()
            if line.startswith('Name'):
                if adapter_found:
                    # Fully processed target name, quit
                    break
                else:
                    adapter_found = True
                    continue
            value = '' if len(line.split(':',1)) == 1 else line.split(':',1)[1].strip()
            if line.startswith('Description'):
                self.desc = value
                continue
            if line.startswith('Physical address'):
                self.mac = value
                continue
            if line.startswith('State'):
                self.connected = value == 'connected'
                continue
            if line.startswith('SSID'):
                self.SSID = value
                continue
            if line.startswith('BSSID'):
                self.BSSID = value
                continue
            if line.startswith('Radio type'):
                self.radio_type = value
                continue
            if line.startswith('Authentication'):
                self.Authentication = value
                continue
            if line.startswith('Cipher'):
                self.cipher = value
                continue
            if line.startswith('Channel'):
                self.channel = int(value)
                continue
            if line.startswith('Receive rate'):
                self.receive_rate = float(value)
                continue
            if line.startswith('Transmit rate'):
                self.transmit_rate = float(value)
                continue
            if line.startswith('Signal'):
                self.signal = int(value.replace('%',''))
                continue

        return adapter_found
    

# ============================================================================================================================
# == Helper routines =========================================================================================================
def identify_scanner(args: argparse.Namespace) -> ScannerBase:
    """
    Return scanner object based on:
    1. command line parameter (if supplied)
    2. OS and installed utilties in order (nmcli, iwlist, iw)
    """
    scanner: ScannerBase = None
    if args.nmcli:  
        scanner = NetworkManagerWiFiScanner(interface=args.interface)
        LOGGER.info('- Scanner nmcli requested (Linux)')
    elif args.iwlist:
        scanner = IwlistWiFiScanner(interface=args.interface)
        LOGGER.info('- Scanner iwlist requested (Linux)')
    elif args.iw:
        scanner = IwWiFiScanner(interface=args.interface)
        LOGGER.info('- Scanner iw requested (Linux)')
    elif args.netsh:
        scanner = WindowsWiFiScanner(interface=args.interface)
        LOGGER.info('- Scanner netsh requested')
    else:
        if running_on_windows():
            LOGGER.info('- Windows Scanner netsh selected')
            scanner = WindowsWiFiScanner(args.interface)
        elif running_on_linux():
            if NetworkManagerWiFiScanner.is_available():
                scanner = NetworkManagerWiFiScanner(args.interface)
                # LOGGER.info('- Linux Scanner nmcli selected')
            elif IwlistWiFiScanner.is_available():
                scanner = IwlistWiFiScanner(args.interface)
                # LOGGER.info('- Linux Scanner iwlist selected')
            else:
                scanner = IwWiFiScanner(args.interface)
                # LOGGER.info('- Linux Scanner iw selected')
        else:
            LOGGER.critical('- OS not supported.')

    return scanner    

def identify_wifi_adapters() -> List[str]:
    """Return list of installed wifi adapers, None if not found"""
    adapters: List[str] = []
    if running_on_linux():
        cmd_output, ret_cd = ScannerBase._execute_process(CONSTANTS.IWCONFIG, show_feedback=False)
        if ret_cd == 0:
            for line in cmd_output:
                if 'ESSID' in line:
                    adapters.append(line.split()[0].strip())
    elif running_on_windows():
        cmd_output, ret_cd = ScannerBase._execute_process('netsh wlan show interfaces', show_feedback=False)
        if ret_cd == 0:
            for line in cmd_output:
                if line.strip().startswith('Name'):
                    adapters.append(line.split(':')[1].strip())

    if len(adapters) > 0:
        return adapters
    
    return None

def adapter_list() -> List[str]:
    """Return list of ALL installed network adapters"""
    # TODO: Build interface list
    adapters = []
    if running_on_linux():
        lines, _ = ScannerBase._execute_process(f'{CONSTANTS.IFCONFIG} -a', False)
        for line in lines:
             if 'flags' in line:
                 iface_name = line.split(':',1)[0].strip()
                 adapters.append(iface_name)
                 
    elif running_on_windows():
        lines, _ = ScannerBase._execute_process('ipconfig /all', False)
        for line in lines:
            if 'adapter' in line and '* ' not in line:
                iface_name = line.split('adapter')[1].replace(':','').strip()
                adapters.append(iface_name)
    else:
        pass # Unsupported OS

    LOGGER.debug(f'- adapters: {", ".join(adapters)}')
    return adapters


# ============================================================================================================================
# == Main Entrypoint =========================================================================================================   
def main() -> int:
    desc = 'Scan for wi-fi access points (Networks)'
    epilog = '''
This utility will scan for network APs (Access Points) using underlying OS utilities
and list related information.

- Supports Linux and Windows. 
- Output options include: formatted (default), csv and json

'''
    development_mode = False
    for arg in sys.argv:
        if arg == '-d':
            development_mode = True
            sys.argv.remove('-d')
            break

    parser = argparse.ArgumentParser(prog="ap_scanner", 
                                     description=desc, formatter_class=argparse.RawTextHelpFormatter,
                                     epilog=epilog)
    parser.add_argument('-i', '--interface', type=str, default=None, metavar='<iface>', help='Interface to use, default=first wireless adapter discovered')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Debug/verbose output to console')
    parser.add_argument('-j', '--json', action='store_true', default=False, help='Output json result')
    parser.add_argument('-c', '--csv', action='store_true', default=False, help='Output csv result')
    parser.add_argument('-r', '--rescan', action='store_true', default=False, help='(Windows only) force network rescan for APs')
    parser.add_argument('--nmcli', action='store_true', default=False, help='Force Linux Network Manager discovery')
    parser.add_argument('--iwlist', action='store_true', default=False, help='Force Linux iwlist discovery')
    parser.add_argument('--iw', action='store_true', default=False, help='Force Linux iw discover')
    parser.add_argument('--netsh', action='store_true', default=False, help='Force Windows netsh discovery')
    if development_mode:
        parser.add_argument('-t', '--test', type=str, default=None, metavar='<filename>', help='Use test data, specify filename')
        parser.add_argument('-s', '--save', type=str, default=None, metavar='<filename>', help='Filename to save (os scan) command output in')

    args = parser.parse_args()

    LOG_LVL = "INFO"
    if args.verbose == 1:
        LOG_LVL = "DEBUG"
    elif args.verbose > 1:
        LOG_LVL = "TRACE"

    # Remove root logger and create console logger
    LOGGER.remove(0) 
    h_console = LOGGER.add(sink=sys.stderr, level=LOG_LVL, format=CONSTANTS.CONSOLE_LOGFORMAT)
    ScannerBase.logging_level = LOG_LVL
    
    header_width = len(desc) + 20
    title = f'{parser.prog} v{version(parser.prog)}'.center(header_width-4, ' ')
    display_desc = desc.center(header_width-4, ' ')
    LOGGER.info('='*header_width)
    LOGGER.info(f'=={title}==')
    LOGGER.info('='*header_width)
    LOGGER.info(f'=={display_desc}==')
    LOGGER.info('='*header_width)
    LOGGER.info('')
    LOGGER.info('Validate command line options')
    
    if development_mode:
        LOGGER.warning('- Development mode enabled')
    else:
        # Disable development mode functionality
        args.test = False
        args.save = False

    wifi_adapters = identify_wifi_adapters()
    if wifi_adapters is None:
        LOGGER.critical('WiFi capabilities required. No Wifi adapter detected.  ABORT')
        return -1
    else:
        LOGGER.info(f'- {len(wifi_adapters)} Wifi adapter(s) detected: {", ".join(wifi_adapters)}')

    if args.interface:
        iface_list = adapter_list()
        if args.interface not in iface_list:
            LOGGER.error(f'- Invalid interface [{args.interface}], valid values: {", ".join(adapter_list())}')
            return -2
    else:
        args.interface = 'wlan0'
        if len(wifi_adapters) > 0:
            args.interface = wifi_adapters[0]

    wifi_adapter = AdapterInfo(args.interface)
    if wifi_adapter.connected:
        LOGGER.info(f'- "{wifi_adapter.name}" will be used to scan via {wifi_adapter.radio_type} [{wifi_adapter.signal}%]')
    else:
        LOGGER.info(f'- "{wifi_adapter.name}" will be used to scan')

    scanner = identify_scanner(args)
    if scanner is None:
        return -3
            
    if args.test:
        if not scanner.set_test_datafile(args.test):
            return -4
        elif args.rescan:
            LOGGER.warning('- TEST MODE: rescan otion ignored')
            args.rescan = False
        elif args.save:
            LOGGER.warning('- TEST MODE: save output option ignored')
            args.save = None
    else:
        # if not scanner.os_check():
        if not os_check(scanner):
            LOGGER.critical(f'Invalid scanner - {scanner.__class__.__name__} only valid for {scanner.scanner_supported_os()}')
            return -5

    if args.rescan:
        if not scanner.rescan():
            return -6
    
    if args.save: 
        scanner.set_output_capture_file(args.save)

    ap_list = scanner.scan_for_access_points()
    if ap_list is None or len(ap_list) == 0:
        LOGGER.error('No Access Points discovered. Process terminating...')
        return -99
    
    LOGGER.success(f'- {len(ap_list)} APs discovered')
    if args.json:
        display_json(ap_list)
    elif args.csv:
        display_csv(ap_list)
    else:
        display_access_points(ap_list)

    LOGGER.info('')
    return 0

if __name__ == "__main__":
    sys.exit(main())
 