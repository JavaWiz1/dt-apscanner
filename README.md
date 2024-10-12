# dt_apscanner


## Command Line Access Point (AP) scanning tool 


### <u>Overview:</u>
This python utility will scan for network Access Points (APs) using underlying OS utilities and list related AP information.

- Supports Linux and Windows. 
- Output options include: formatted (default), csv and json


### <u>Install:</u>
```
pip install dt-apscanner
```

or for source code:

```
git clone https://github.com/JavaWiz1/dt-apscanner.git
```

Note: poetry is used for dependency management and packaging

### <u>Usage:</u>
```
usage: dt_apscanner [-h] [-i <iface>] [-r] [-j] [-c] [-v] [--nmcli] [--iwlist] [--iw] [--netsh]

Scan for wi-fi access points (Networks)

options:
  -h, --help            show this help message and exit
  -i <iface>, --interface <iface>
                        (Linux only) Interface to use, default=wlan0
  -r, --rescan          (Windows only) force network rescan for APs
  -j, --json            Output json result
  -c, --csv             Output csv result
  -v, --verbose         Debug/verbose output to console
  --nmcli               Force Linux Network Manager discovery
  --iwlist              Force Linux iwlist discovery
  --iw                  Force Linux iw discover
  --netsh               Force Windows netsh discovery

This utility will scan for network APs (Access Points) using underlying OS utilities
and list related information.

- Supports Linux and Windows.
- Output options include: formatted (default), csv and json
```


### <u>Examples:</u>
Windows - trigger re-scan to get most current list of access points
```
> dt_apscanner -r
===========================================================
==                  dt_apscanner v0.1.2                  ==
===========================================================
==        Scan for wi-fi access points (Networks)        ==
===========================================================

Validate command line options
- 1 Wifi adapter(s) detected: Wi-Fi
- "Wi-Fi" will be used to scan via 802.11ac [99%]
- Windows Scanner netsh selected

Rescan requested
- Autoconnect enabled for MyLAN1
- Disconnect to trigger re-scan of network

Scan for access points (WindowsWiFiScanner)
- Executing: netsh wlan show network mode=bssid

Process results of scan
- 5 APs discovered

SSID                      Auth            Encryption Mac Address       Signal Radio    Band    Channel
------------------------- --------------- ---------- ----------------- ------ -------- ------- -------
MyLAN1                    WPA2-Personal   CCMP       0c:9a:91:2c:bb:28   99%  802.11n  Unknown       3
                                                     0c:9a:91:2c:bb:2c   99%  802.11ac Unknown      36
NETGEAR99                 WPA2-Personal   CCMP       b0:41:a0:85:0f:d6   99%  802.11n  Unknown       3
**hidden**                WPA2-Enterprise CCMP       dc:eb:62:0a:b0:8b   33%  802.11n  Unknown       1
                                                     42:f1:9a:6d:5c:7b   21%  802.11n  Unknown       1
                                                     22:47:5c:fa:01:39   18%  802.11ac Unknown       6
Nirvana                   Open            None       f4:cf:b2:ac:bd:b1   58%  802.11n  Unknown       1
ThePond                   WPA2-Personal   CCMP       7c:80:26:01:70:de   51%  802.11n  Unknown       1
```

Linux - Use wlan2 connection for scan and use Network Manager (nmcli) for discovery
```
> dt_apscanner -i wlan2 --nmcli
===========================================================
==                   dt_apscanner v0.1.1                   ==
===========================================================
==        Scan for wi-fi access points (Networks)        ==
===========================================================

Validate command line options
- 1 Wifi adapter(s) detected: wlan2
- "wlan2" will be used to scan

Scan for access points (NetworkManagerWiFiScanner)
- Executing: /usr/bin/nmcli -t -f ssid,bssid,chan,freq,signal,security,rsn-flags device wifi list

Process results of scan
- 5 APs discovered

SSID                      Auth            Encryption Mac Address       Signal Radio    Band    Channel
------------------------- --------------- ---------- ----------------- ------ -------- ------- -------
MyLAN1                    WPA2-Personal   CCMP       0C-9A-91-2C-BB-28  100%  Unknown  2.4 MHz       3
NETGEAR99                 WPA2-Personal   CCMP       B0-41-A0-85-0F-D6  100%  Unknown  2.4 MHz       3
**hidden**                WPA2-Personal   CCMP       88-9E-62-1D-3E-1A  100%  Unknown  2.4 MHz      11
Nirvana                   Open            None       F4-CF-B2-AC-BD-B1   44%  Unknown  2.4 MHz       1
ThePond                   WPA2-Personal   CCMP       7C-80-26-01-70-DE   44%  Unknown  2.4 MHz       1
```

### <u>Notes:</u>
- On windows, you can rescan (-r) and search for current networks
- You may save the outut of the underlying command into a file (-s)
- You can force which method searches for networks:
  - Linux:   nmcli, iw, iwlist
  - Windows: netsh
- Tested on
  - Windows 10/11
  - Ubuntu Ubuntu 22.04.3 LTS
  - RaspPi OS - Debian GNU/Linux 11 (bullseye) / Raspbian GNU/Linux 10 (buster)


### <u>ToDo:</u>
- Identify Band (i.e 2.4 MHz / 5 Mhz) on Windows
- Radio identification for Linux (802.11xx)
- Add Apple MAC capability
- Create unit tests