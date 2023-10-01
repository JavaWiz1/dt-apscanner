import argparse
import json
import pathlib
import platform
import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from time import sleep
from typing import Dict, List, Tuple

from loguru import logger as LOGGER

# ============================================================================================================================   
# TODO: 
# - Add version to output description
# - Update pyproject.toml to create script shortcuts
# - build test suites for unit testing
#
# Tests:
#   scanner.supported_os()
#   
# == Module Variables ========================================================================================================   
class CONSTANTS:
    UNKNOWN = 'Unknown'
    HIDDEN = " **hidden**"
    BAND24 = '2.4 MHz'
    BAND5  = '5 MHz'
    WINDOWS = "Windows"
    LINUX = "Linux"
    FILE_LOGFORMAT = "<green>{time:MM/DD/YY HH:mm:ss}</green> |<level>{level: <8}</level>|<cyan>{name:10}</cyan>|<cyan>{line:3}</cyan>| <level>{message}</level>"
    CONSOLE_LOGFORMAT = "<level>{message}</level>"
    NMCLI = '/usr/bin/nmcli'
    IW = '/usr/sbin/iw'
    IWLIST = '/usr/sbin/iwlist'
    IWCONFIG = '/usr/sbin/iwconfig'
    IFCONFIG = '/usr/sbin/ifconfig'

AUTH_MAP = {
    "PSK": "WPA2-Personal",
    "WPA2": "WPA2-Personal",
    "IEEE 802.1X": "WPA2-Enterprise",
    "802.1x": "WPA2-Enterprise",
    "WPA1 WPA2 802.1X": "WPA2-Enterprise"
}

@dataclass
class BSSID:
    mac: str
    signal: int = -1
    radio_type: str = CONSTANTS.UNKNOWN
    band: str = CONSTANTS.UNKNOWN
    channel: int = -1

@dataclass
class SSID:
    name: str
    net_type: str = CONSTANTS.UNKNOWN
    auth: str = 'Open'
    encryption: str = 'None'

@dataclass
class AccessPoint:
    ssid: SSID
    bssid: List[BSSID] = field(default_factory=list)


# == Scanner Objects =========================================================================================================   
@dataclass
class ScannerBase(ABC):
    interface: str = 'wlan0'
    test_datafile: pathlib.Path = None
    output_datafile: pathlib.Path = None
    
    @abstractmethod
    def scanner_supported_os(self) -> str:
        LOGGER.warning(f'- Rescan NOT supported for {self.__class__.__name__}')

    @abstractmethod
    def rescan(self) -> bool:
        LOGGER.error(f'Rescan is not supported in {self.__class__.__name__}')
        return False

    @abstractmethod
    def _process_output(self) -> str:
        """Function to process command output based on Scanner"""
        pass

    def scan_for_access_points(self) -> List[AccessPoint]:
        cmd_output = self._scan()
        LOGGER.info('- Process results of scan')
        return self._process_output(cmd_output)
    
    def _scan(self) -> List[AccessPoint]:
        LOGGER.info('Scan for access points (networks)')
        if self.test_datafile is not None:
            cmd_output = self._get_raw_data()
        else:
            cmd = self.scan_cmd.replace('%interface%', self.interface)
            cmd_output = self._execute_process(cmd)
            if self.output_datafile:
                try:
                    self.output_datafile.write_text('\n'.join(cmd_output))
                    LOGGER.success(f'- Output saved to: {self.output_datafile}')
                except Exception as ex:
                    LOGGER.error(f'- Unable to save output to {self.output_datafile}: {repr(ex)}')
        
        return cmd_output

    def set_output_capture_file(self, filenm: str):
        self.output_datafile = pathlib.Path(filenm)
        if self.output_datafile.is_file():
            LOGGER.debug(f"- Output saved to '{filenm}'")
        else:
            LOGGER.warning(f"- Output file: '{filenm}' not valid, will NOT save output")
            self.output_datafile = ''

    def set_test_datafile(self, filenm: str) -> bool:
        """Set test data filename"""
        self.test_datafile = pathlib.Path(filenm)
        if self.test_datafile.exists():
            LOGGER.debug(f"- Test data file '{self.test_datafile}' exists ")
        else:
            self.test_datafile = None
            LOGGER.error(f"- TEST MODE: test data file: '{filenm}' not found.")
            return False
        return True
    
    def os_check(self) -> bool:
        if running_on_windows() and self.scanner_supported_os() == CONSTANTS.WINDOWS:
            return True
        elif running_on_linux() and self.scanner_supported_os() == CONSTANTS.LINUX:
            return True

        return False
    
    @classmethod
    def _get_ap_ssid_entry(cls, ssid_name: str, mac: str, ap_list: List[AccessPoint]) -> Tuple[int, AccessPoint]:
        ap_entry: AccessPoint = None
        tgt_idx = -1
        found = False
        for idx in range(len(ap_list)):
            if ap_list[idx].ssid.name == ssid_name:
                found = True

            if found:
                ap_entry = ap_list[idx]
                tgt_idx = idx
                break

        return tgt_idx, ap_entry
        
    @classmethod
    def _execute_process(cls, cmd: str, show_feedback: bool = True) -> List[str]:
        """Run the (scan) command and return output as a list of strings"""
        cmd_list = cmd.split()
        try:
            if show_feedback:
                LOGGER.info(f'- Executing: {cmd}')
            cmd_output = subprocess.check_output(cmd_list, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as cpe:
            #print (netsh_output)
            cmd_output = bytes(f'{repr(cpe)}', 'ascii')

        # decode it to strings
        lines = cmd_output.decode('ascii').replace('\r', '').splitlines()
        return lines
    
    def _get_raw_data(self) -> List[str]:
        data_file = pathlib.Path(self.test_datafile)
        result = ''
        if not data_file.exists():
            LOGGER.error(f'- TEST MODE: data file does not exist. {data_file}')
            raise FileNotFoundError(data_file)
        else:
            LOGGER.warning(f'- TEST MODE: data read from {data_file}')
            result = data_file.read_text()
          
        return result.splitlines()
    

# ===========================================================================================================================   
class WindowsWiFiScanner(ScannerBase):
    scan_cmd = 'netsh wlan show network mode=bssid'

    cmd_force_rescan = 'netsh wlan disconnect'
    interface = None

    def scanner_supported_os(self) -> str:
        return "Windows"
    
    def rescan(self) -> bool:
        LOGGER.info('Rescan requested')
        connections_dict = self._connected_to_profiles()
        autoconnect_enabled = False
        for profile, ap in connections_dict.items():
            if self._profile_autoconnect(profile):
                LOGGER.info(f'- Autoconnect enabled for {profile}')
                autoconnect_enabled = True
        
        if not autoconnect_enabled:
            LOGGER.warning('  There are no wifi autoconnections enabled, you will have to manually recoonect to network.')
            if get_input('  continue (y/n)? ',['y','n']) == 'n':
                return False
            
        LOGGER.info('- Disconnect to trigger re-scan of network')
        netsh_output = self._execute_process(self.cmd_force_rescan)
        sleep(5)
        return True
    
    def _process_output(self, netsh_lines: list) -> List[AccessPoint]:
        ap = None
        ap_list = []
        bssid_list = []
        ssid_info: SSID = SSID(CONSTANTS.UNKNOWN)
        bssid_info: BSSID = BSSID(CONSTANTS.UNKNOWN)
        for line in netsh_lines:
            line = line.strip()            
            tokens = line.split(":", maxsplit=1)
            keyword = tokens[0].strip()
            value = '' if len(tokens) == 1 else tokens[1].strip()
            if keyword.startswith("SSID"):
                if ssid_info.name != CONSTANTS.UNKNOWN:
                    # Output last access point definition
                    if bssid_info.mac != CONSTANTS.UNKNOWN:
                        bssid_list.append(bssid_info)
                    ap = AccessPoint(ssid_info, bssid_list)
                    ap_list.append(ap)
                name = value if len(value) > 0 else CONSTANTS.HIDDEN
                ssid_info = SSID(name)
                bssid_info = BSSID(CONSTANTS.UNKNOWN)
                bssid_list = []
            elif keyword.startswith("Network type"):
                ssid_info.net_type = value
            elif keyword.startswith("Authentication"):
                ssid_info.auth = value
            elif keyword.startswith("Encryption"):
                ssid_info.encryption = value
            elif keyword.startswith("BSSID"):
                if bssid_info.mac != CONSTANTS.UNKNOWN:
                    bssid_list.append(bssid_info)
                bssid_info = BSSID(value)
            elif keyword.startswith("Signal"):
                bssid_info.signal = int(value.replace('%',''))
            elif keyword.startswith("Radio type"):
                bssid_info.radio_type = value
            elif keyword.startswith("Band"):
                bssid_info.band = value
            elif keyword.startswith("Channel"):
                bssid_info.channel = int(value)

        if ssid_info.name != CONSTANTS.UNKNOWN:
            # Append the last access point
            if bssid_info.mac != CONSTANTS.UNKNOWN:
                bssid_list.append(bssid_info)
            ap = AccessPoint(ssid_info, bssid_list)
            ap_list.append(ap)        

        return ap_list

    def _profiles(self) -> List[str]:
        profiles = []
        netsh_output = self._execute_process('netsh wlan show profiles', False)
        for line in netsh_output:
            line = line.strip()
            if line.startswith("All User Profile"):
                profiles.append(line.split(':')[1].strip())
        
        return profiles

    def _profile_autoconnect(self, profile: str) -> bool:
        auto_connect = False
        cmd = f'netsh wlan show profile {profile}'
        netsh_output = self._execute_process(cmd, False)
        for line in netsh_output:
            line = line.strip()
            if line.startswith('Connection mode'):
                if "Connect automatically" in line:
                    auto_connect = True
                break

        return auto_connect
    
    def _connected_to_profiles(self) -> Dict[str, AccessPoint]:
        """
        Return a dictionary of connections, listing wlan profile and associated access point info in format
        {"ProfileName": AccessPoint, ...}
        """
        connected_profiles = {}
        iface = ''
        connected = False
        profile = ''
        ap_list = List[AccessPoint]
        netsh_output = self._execute_process('netsh wlan show interfaces', False)
        for line in netsh_output:
            line = line.strip()
            value = '' if ':' not in line else line.split(':', 1)[1].strip()
            if line.startswith('Name'):
                if iface != '':
                    if connected:
                        ap = AccessPoint(ssid_info, [bssid_info])
                        connected_profiles[profile] = ap
                iface = value
                connected = False
                profile = ''
                ssid_info = SSID(CONSTANTS.UNKNOWN)
                bssid_info = BSSID(CONSTANTS.UNKNOWN)                
            elif line.startswith('SSID'):
                ssid_info.name = value
            elif line.startswith('BSSID'):
                bssid_info.mac = value
            elif line.startswith('Radio'):
                bssid_info.radio_type = value
            elif line.startswith('Authentication'):
                ssid_info.auth = value
            elif line.startswith('Cipher'):
                ssid_info.encryption = value
            elif line.startswith('Channel'):
                bssid_info.channel = value
            elif line.startswith('Signam'):
                bssid_info.signal = value.replace('%','')
            elif line.startswith('State'):
                connected = True if value == 'connected' else False
            elif line.startswith('Profile'):
                profile = value

        if iface != '':
            if connected:
                ap = AccessPoint(ssid_info, [bssid_info])
                connected_profiles[profile] = ap

        return connected_profiles
    
# ===========================================================================================================================   
class IwWiFiScanner(ScannerBase):
    scan_cmd = f'sudo {CONSTANTS.IW} dev %interface% scan'
    
    def scanner_supported_os(self) -> str:
        return "Linux"

    def rescan(self) -> bool:
        return super().rescan()
    
    def _process_output(self, data_list: List[str]) -> List[AccessPoint]:
        results: List[AccessPoint] = []

        ssid_info: SSID = SSID(CONSTANTS.UNKNOWN)
        bssid_info: BSSID = BSSID(CONSTANTS.UNKNOWN)
        bssid_list = []
        for line in data_list:
            line = line.strip()
            value = CONSTANTS.UNKNOWN if ':' not in line else line.split(':',1)[1].strip()
            if line.startswith('BSS') and line != 'BSS Load:':
                if ssid_info.name != CONSTANTS.UNKNOWN:
                    # New entry, append/update list
                    idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
                    if ap is not None and ap.ssid.name != CONSTANTS.HIDDEN:
                        ap.bssid.append(bssid_info)
                        results[idx] = ap
                    else:
                        bssid_list.append(bssid_info)
                        ap = AccessPoint(ssid_info, bssid_list)
                        results.append(ap)
                    ssid_info = SSID(CONSTANTS.UNKNOWN)
                    bssid_info = BSSID(CONSTANTS.UNKNOWN)
                    bssid_list = []
                mac = line.replace('BSS ','').split('(')[0].strip()
                bssid_info.mac = mac
            elif line.startswith('freq'):
                bssid_info.band = self._resolve_band(value)
            elif line.startswith('signal'):
                bssid_info.signal = self._resolve_signal_strength(value.split()[0])
            elif line.startswith('SSID'):
                ssid_info.name = value
                if ssid_info.name == '':
                    ssid_info.name = CONSTANTS.HIDDEN # last_ssid_name
            elif line.startswith('* primary channel'):
                bssid_info.channel = int(value)
            elif line.startswith('* Group cipher'):
                ssid_info.encryption = value
            elif line.startswith('* Authentication'):
                ssid_info.auth = AUTH_MAP.get(value, value)

        if ssid_info.name != CONSTANTS.UNKNOWN:
            # New entry, append/update list
            idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
            if ap is not None:
                ap.bssid.append(bssid_info)
                results[idx] = ap
            else:
                bssid_list.append(bssid_info)
                ap = AccessPoint(ssid_info, bssid_list)
                results.append(ap)

        return results
    
    def _resolve_signal_strength(self, freq) -> int:
        i_freq = float(freq)
        sig_strength = int((-33 / i_freq) * 100)
        sig_strength = min(100, sig_strength)
        sig_strength = max(0, sig_strength)
        return sig_strength

    def _resolve_band(self, freq_str: str) -> str:
        if freq_str.startswith('24'):
            return CONSTANTS.BAND24
        elif freq_str.startswith('5'):
            return CONSTANTS.BAND5

        return ''
    
    
# ===========================================================================================================================   
class NetworkManagerWiFiScanner(ScannerBase):
    scan_cmd = f'{CONSTANTS.NMCLI} -t -f ssid,bssid,chan,freq,signal,security,rsn-flags device wifi list'

    def scanner_supported_os(self) -> str:
        return "Linux"

    def rescan(self) -> bool:
        return super().rescan()

    def _process_output(self, data_list: List[str]) -> List[AccessPoint]:
        results: List[AccessPoint] = []

        ssid_info: SSID = None
        bssid_info: BSSID = None
        bssid_list = []
        last_ssid = None
        ssid = None
        for line in data_list:
            line = line.replace("\\:", "-")
            tokens = line.split(':')
            ssid = CONSTANTS.HIDDEN if len(tokens[0]) == 0 else tokens[0]
            mac = tokens[1]
            if len(ssid) > 0 and last_ssid is not None:
                # We have full definition, append to list
                ap = AccessPoint(ssid_info, bssid_list)
                results.append(ap)
            if len(ssid) > 0:
                last_ssid = ssid
                # Start creating new entry
                ssid_info = SSID(ssid)
                value = tokens[5] if len(tokens[5]) > 0 else 'Open'
                ssid_info.auth = AUTH_MAP.get(value, value)
                ssid_info.net_type = CONSTANTS.UNKNOWN
                ssid_info.encryption = 'CCMP' if 'ccmp' in tokens[6] else 'None'
                bssid_list = []
            bssid_info = BSSID(mac)
            bssid_info.channel = int(tokens[2])
            bssid_info.radio_type = CONSTANTS.UNKNOWN
            bssid_info.signal = int(tokens[4])
            bssid_info.band = self._resolve_band(tokens[3])
            bssid_list.append(bssid_info)

        if ssid is not None:
            # Append last entry
            ap = AccessPoint(ssid_info, bssid_list)
            results.append(ap)

        return results
    
    @classmethod
    def is_running(cls) -> bool:
        nmcli_output = cls._execute_process(CONSTANTS.NMCLI)
        LOGGER.debug(f'nmcli is_running() output:')
        LOGGER.debug(nmcli_output)
        for line in nmcli_output:
            if "is not running" in line:
                return False
        return True
    
    def _resolve_band(self, freq_str: str) -> str:
        if freq_str.startswith('24'):
            return CONSTANTS.BAND24
        elif freq_str.startswith('5'):
            return CONSTANTS.BAND5
        return ''
    

# ===========================================================================================================================   
class IwlistWiFiScanner(ScannerBase):
    scan_cmd = f'sudo {CONSTANTS.IWLIST} %interface% scanning'

    def scanner_supported_os(self) -> str:
        return "Linux"    

    def rescan(self) -> bool:
        return super().rescan()

    def _process_output(self, data_list: List[str]) -> List[AccessPoint]:
        results: List[AccessPoint] = []
        bssid_list: List[BSSID] = []
        ssid_info = SSID(CONSTANTS.UNKNOWN)
        bssid_info = BSSID(CONSTANTS.UNKNOWN)
        for line in data_list:
            line = line.strip()
            value = CONSTANTS.UNKNOWN if ':' not in line else line.split(':',1)[1].strip()
            if line.startswith('IE') and value.startswith(CONSTANTS.UNKNOWN):
                pass
            else:
                if line.startswith('Cell'):
                    if ssid_info.name != CONSTANTS.UNKNOWN:
                        # New entry, append/update list
                        idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
                        if ap is not None:
                            ap.bssid.append(bssid_info)
                            results[idx] = ap
                        else:
                            bssid_list.append(bssid_info)
                            ap = AccessPoint(ssid_info, bssid_list)
                            results.append(ap)
                        ssid_info = SSID(CONSTANTS.UNKNOWN)
                        bssid_info = BSSID(CONSTANTS.UNKNOWN)
                        bssid_list = []
                    bssid_info.mac = value
                elif line.startswith('Channel'):
                    bssid_info.channel = int(value.replace('-',":"))
                elif line.startswith('Frequency'):
                    bssid_info.band = self._resolve_band(value)
                elif line.startswith('Quality'):
                    txt_sig = line.split('=')[1].split()[0]
                    signals = txt_sig.split('/')
                    bssid_info.signal = int(int(signals[0]) / int(signals[1]) * 100)
                elif line.startswith('ESSID'):
                    ssid_info.name = value.replace('"','')
                    if ssid_info.name == '':
                        ssid_info.name = CONSTANTS.HIDDEN # last_ssid_name
                elif line.startswith('Group Cipher'):
                    ssid_info.encryption = value
                elif line.startswith('Authentication Suites'):
                    ssid_info.auth = AUTH_MAP.get(value, value)
        
        if ssid_info.name is not None:
            # Last entry
            idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
            if ap is not None:
                ap.bssid.append(bssid_info)
                results[idx] = ap
            else:
                bssid_list.append(bssid_info)
                ap = AccessPoint(ssid_info, bssid_list)
                results.append(ap)            

        return results

    @classmethod
    def is_running(cls) -> bool:
        iwlist_output = cls._execute_process(cls.cmd)
        if "doesn't support scanning" in iwlist_output:
            return False
        return True

    def _resolve_band(self, freq_str: str) -> str:
        if freq_str.startswith('2.4'):
            return CONSTANTS.BAND24
        elif freq_str.startswith('5.'):
            return CONSTANTS.BAND5
        return ''
    

# == Display output routines =================================================================================================   
def todict(obj, classkey=None):
    """Recursively translate object into dictionary"""
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = todict(v, classkey)
        return data
    elif hasattr(obj, "_ast"):
        return todict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [todict(v, classkey) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, todict(value, classkey)) 
            for key, value in obj.__dict__.items() 
            if not callable(value) and not key.startswith('_')])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    else:
        return obj

def display_access_points(ap_list: List[AccessPoint]):
    LOGGER.info('')
    LOGGER.info('SSID                      Auth            Encryption Mac Address       Signal Radio    Band    Channel')
    LOGGER.info('------------------------- --------------- ---------- ----------------- ------ -------- ------- -------')
    for sidx in range(len(ap_list)):
        ap = ap_list[sidx]
        bssid = ap.bssid[0]
        LOGGER.info(f'{ap.ssid.name:25} {ap.ssid.auth:15} {ap.ssid.encryption:10} {bssid.mac:17} {bssid.signal:4}%  {bssid.radio_type:8} {bssid.band:7} {bssid.channel:7}')
        for bidx in range(1, len(ap.bssid)):
            bssid = ap.bssid[bidx]
            LOGGER.info(f'{" "*52} {bssid.mac:17} {bssid.signal:4}%  {bssid.radio_type:8} {bssid.band:7} {bssid.channel:7}')

def display_json(ap_list: List[AccessPoint]):
    LOGGER.info('- json output')
    print(json.dumps(todict(ap_list),indent=2))

def display_csv(ap_list: List[AccessPoint]):
    LOGGER.info('- csv output')
    print('ssid,auth,encryption,mac,signal,type,band,channel')
    for ap in ap_list:
        ssid_info = f'{ap.ssid.name},{ap.ssid.auth},{ap.ssid.encryption}'
        for bssid in ap.bssid:
            bssid_info = f'{bssid.mac},{bssid.signal},{bssid.radio_type},{bssid.band},{bssid.channel}'
            print(f'{ssid_info},{bssid_info}')


# == Helper routines =========================================================================================================
def wifi_adapters() -> List[str]:
    adapters: List[str] = []
    if running_on_linux():
        cmd_output = ScannerBase._execute_process(CONSTANTS.IWCONFIG, show_feedback=False)
        if len(cmd_output) > 0:
            for line in cmd_output:
                if 'ESSID' in line:
                    adapters.append(line.split()[0].strip())
    elif running_on_windows():
        cmd_output = ScannerBase._execute_process('netsh wlan show interfaces', show_feedback=False)
        if len(cmd_output) > 0:
            for line in cmd_output:
                if line.strip().startswith('Name'):
                    adapters.append(line.split(':')[1].strip())

    LOGGER.debug(f'- Wifi adapters: {", ".join(adapters)}')
    if len(adapters) > 0:
        return adapters
    
    return None

def interface_list() -> List[str]:
    # TODO: Build interface list
    adapters = []
    if running_on_linux():
        lines = ScannerBase._execute_process(f'{CONSTANTS.IFCONFIG} -a', False)
        for line in lines:
             if 'flags' in line:
                 iface_name = line.split(':',1)[0].strip()
                 adapters.append(iface_name)
                 
    elif running_on_windows():
        lines = ScannerBase._execute_process('ipconfig /all', False)
        for line in lines:
            if 'adapter' in line and '* ' not in line:
                iface_name = line.split('adapter')[1].replace(':','').strip()
                adapters.append(iface_name)
    else:
        pass # Unsupported OS

    return adapters

def running_on_linux() -> bool:
    return platform.system() == "Linux"

def running_on_windows() -> bool:
    return platform.system() == "Windows"

def get_input(prompt: str, valid_responses: list = [], default: str = None) -> str:
    """
    Prompt for input with a timer
    Parameters:
        prompt          - req - text to display
        valid_responses - opt - stringco or list of valid responses (default None)
        default         - opt - default vault returned (default None)
    """
    valid_input = False
    while not valid_input:
        response = input(prompt)
        if not valid_responses:
            LOGGER.debug('no valid responses to check')
            valid_input = True
        else:
            if response in valid_responses:
                valid_input = True

    return response


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
    parser.add_argument('-i', '--interface', type=str, default=None, metavar='<iface>', help='(Linux only) Interface to use, default=wlan0')
    parser.add_argument('-r', '--rescan', action='store_true', default=False, help='(Windows only) force network rescan for APs')
    parser.add_argument('-j', '--json', action='store_true', default=False, help='Output json result')
    parser.add_argument('-c', '--csv', action='store_true', default=False, help='Output csv result')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Debug/verbose output to console')
    if development_mode:
        parser.add_argument('-t', '--test', type=str, default=None, metavar='<filename>', help='Use test data, specify filename')
        parser.add_argument('-s', '--save', type=str, default=None, metavar='<filename>', help='Filename to save (os scan) command output in')
    parser.add_argument('--nmcli', action='store_true', default=False, help='Force Linux Network Manager discovery')
    parser.add_argument('--iwlist', action='store_true', default=False, help='Force Linux iwlist discovery')
    parser.add_argument('--iw', action='store_true', default=False, help='Force Linux iw discover')
    parser.add_argument('--netsh', action='store_true', default=False, help='Force Windows netsh discovery')

    args = parser.parse_args()

    LOG_LVL = "INFO"
    if args.verbose:
        LOG_LVL = "DEBUG"

    # Remove root logger and create console logger
    LOGGER.remove(0) 
    h_console = LOGGER.add(sink=sys.stderr, level=LOG_LVL, format=CONSTANTS.CONSOLE_LOGFORMAT)
    
    LOGGER.info('-'*len(desc))
    LOGGER.info(desc)
    LOGGER.info('-'*len(desc))
    LOGGER.info('Validate command line options')
    
    if development_mode:
        LOGGER.warning('- Development mode enabled')
    else:
        # Disable development mode functionality
        args.test = False
        args.save = False

    adapters = wifi_adapters()
    if adapters is None:
        LOGGER.critical('WiFi capabilities required. No Wifi adapter detected.  ABORT')
        return -1
    else:
        LOGGER.info(f'- Wifi adapter(s): {", ".join(adapters)}')

    if args.interface:
        iface_list = interface_list()
        if args.interface not in iface_list:
            LOGGER.error(f'- Invalid interface [{args.interface}], valid values: {", ".join(interface_list())}')
            return -2
    else:
        args.interface = 'wlan0'
    
    # Check for forced disovery method
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
        # Determine scanner based on OS
        if running_on_windows():
            LOGGER.info('- Scanner netsh selected (Windows)')
            scanner = WindowsWiFiScanner(args.interface)
        elif running_on_linux():
            if NetworkManagerWiFiScanner.is_running():
                scanner = NetworkManagerWiFiScanner(args.interface)
                LOGGER.info('- Scanner nmcli selected (Linux)')
            else:
                scanner = IwlistWiFiScanner(args.interface)
                LOGGER.info('- Scanner iwlist selected (Linux)')
        else:
            LOGGER.critical('- OS not supported.')
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
        if not scanner.os_check():
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
 