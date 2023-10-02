import json
import platform
from typing import List

from loguru import logger as LOGGER

from scanner import CONSTANTS, AccessPoint, ScannerBase


def running_on_linux() -> bool:
    """Return True if running on Linux OS, else False"""
    return platform.system() == "Linux"

def running_on_windows() -> bool:
    """Return True if running on Windows OS, else False"""
    return platform.system() == "Windows"


def os_check(scanner: ScannerBase) -> bool:
    """Return True if running on supported OS, else False"""
    if running_on_windows() and scanner.scanner_supported_os() == CONSTANTS.WINDOWS:
        return True
    elif running_on_linux() and scanner.scanner_supported_os() == CONSTANTS.LINUX:
        return True

    return False

def get_input(prompt: str, valid_responses: list = [], default: str = None) -> str:
    """
    Prompt for valid input
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


def to_dict(obj, classkey=None):
    """Recursively translate object into dictionary format"""
    if isinstance(obj, dict):
        data = {}
        for (k, v) in obj.items():
            data[k] = to_dict(v, classkey)
        return data
    elif hasattr(obj, "_ast"):
        return to_dict(obj._ast())
    elif hasattr(obj, "__iter__") and not isinstance(obj, str):
        return [to_dict(v, classkey) for v in obj]
    elif hasattr(obj, "__dict__"):
        data = dict([(key, to_dict(value, classkey)) 
            for key, value in obj.__dict__.items() 
            if not callable(value) and not key.startswith('_')])
        if classkey is not None and hasattr(obj, "__class__"):
            data[classkey] = obj.__class__.__name__
        return data
    else:
        return obj

#===========================================================================================================================
#== Output routines
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
    print(json.dumps(to_dict(ap_list),indent=2))

def display_csv(ap_list: List[AccessPoint]):
    """Display AccessPoint output in csv format"""
    LOGGER.info('- csv output')
    print('ssid,auth,encryption,mac,signal,type,band,channel')
    for ap in ap_list:
        ssid_info = f'{ap.ssid.name},{ap.ssid.auth},{ap.ssid.encryption}'
        for bssid in ap.bssid:
            bssid_info = f'{bssid.mac},{bssid.signal},{bssid.radio_type},{bssid.band},{bssid.channel}'
            print(f'{ssid_info},{bssid_info}')

