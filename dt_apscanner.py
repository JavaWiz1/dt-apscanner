import argparse
import json
import sys
from typing import List, Tuple

import dt_tools.logger.logging_helper as lh
from dt_tools.misc.helpers import ObjectHelper
from dt_tools.net.nic import (_CONSTANTS, ScannerBase, WifiAdapterInfo,
                              identify_all_adapters, identify_wifi_adapters)
from dt_tools.net.wifi_scanner import (AccessPoint, IwlistWiFiScanner,
                                       IwWiFiScanner,
                                       NetworkManagerWiFiScanner,
                                       WindowsWiFiScanner)
from dt_tools.os.os_helper import OSHelper
from dt_tools.os.project_helper import ProjectHelper
from loguru import logger as LOGGER


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
        if OSHelper.is_windows():
            LOGGER.info('- Windows Scanner netsh selected')
            scanner = WindowsWiFiScanner(args.interface)
        elif OSHelper.is_linux():
            if NetworkManagerWiFiScanner.is_available():
                scanner = NetworkManagerWiFiScanner(args.interface)
            elif IwlistWiFiScanner.is_available():
                scanner = IwlistWiFiScanner(args.interface)
            else:
                scanner = IwWiFiScanner(args.interface)
        else:
            LOGGER.critical('- OS not supported.')

    return scanner    


def os_check(scanner: ScannerBase) -> bool:
    """Return True if running on supported OS, else False"""
    if OSHelper.is_windows() and scanner.scanner_supported_os() == _CONSTANTS.WINDOWS:
        return True
    elif OSHelper.is_linux() and scanner.scanner_supported_os() == _CONSTANTS.LINUX:
        return True

    return False

# ============================================================================================================================
# == Output display routines =================================================================================================
def display_access_points(ap_list: List[AccessPoint]):
    """Display formatted AccessPoint output"""
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
    """Display AccessPoint output in json format"""
    LOGGER.info('- json output')
    print(json.dumps(ObjectHelper.to_dict(ap_list),indent=2))

def display_csv(ap_list: List[AccessPoint]):
    """Display AccessPoint output in csv format"""
    LOGGER.info('- csv output')
    print('ssid,auth,encryption,mac,signal,type,band,channel')
    for ap in ap_list:
        ssid_info = f'{ap.ssid.name},{ap.ssid.auth},{ap.ssid.encryption}'
        for bssid in ap.bssid:
            bssid_info = f'{bssid.mac},{bssid.signal},{bssid.radio_type},{bssid.band},{bssid.channel}'
            print(f'{ssid_info},{bssid_info}')


def _setup_parser(argv: list) -> Tuple[argparse.ArgumentParser, bool]:
    desc = 'Scan for wi-fi access points (Networks)'
    epilog = '''
This utility will scan for network APs (Access Points) using underlying OS utilities
and list related information.

- Supports Linux and Windows. 
- Output options include: formatted (default), csv and json

'''
    development_mode = False
    if '-d' in sys.argv:
        development_mode = True
        sys.argv.remove('-d')
    parser = argparse.ArgumentParser(description=desc, formatter_class=argparse.RawTextHelpFormatter,
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

    return parser, development_mode

# ============================================================================================================================
# == Main Entrypoint =========================================================================================================   
def main() -> int:
    parser, development_mode = _setup_parser(sys.argv)
    args = parser.parse_args()

    LOG_LVL = "INFO"
    if args.verbose == 1:
        LOG_LVL = "DEBUG"
    elif args.verbose > 1:
        LOG_LVL = "TRACE"

    # Remove root logger and create console logger
    LOGGER.remove(0) 
    h_console = LOGGER.add(sink=sys.stderr, level=LOG_LVL, format=lh.DEFAULT_CONSOLE_LOGFMT)  # noqa: F841
    ScannerBase.logging_level = LOG_LVL
    
    header_width = len(parser.description) + 60
    title = f'{parser.prog} v{ProjectHelper.determine_version("dt-apscanner")}'.center(header_width-4, ' ')
    display_desc = parser.description.center(header_width-4, ' ')
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
        LOGGER.critical('- WiFi capabilities required. No Wifi adapter detected.  ABORT')
        return -1
    else:
        LOGGER.info(f'- {len(wifi_adapters)} Wifi adapter(s) detected: {", ".join(wifi_adapters)}')

    if args.interface:
        iface_list = identify_all_adapters()
        if args.interface not in iface_list:
            LOGGER.error(f'- Invalid interface [{args.interface}], valid values: {", ".join(identify_all_adapters())}')
            return -2
    else:
        args.interface = 'wlan0'
        if len(wifi_adapters) > 0:
            args.interface = wifi_adapters[0]

    wifi_adapter = WifiAdapterInfo(args.interface)
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
 