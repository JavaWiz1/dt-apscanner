# ap_scanner

## Command Line Access Point (AP) scanning tool 


### <u>Overview:</u>
This utility will scan for network APs (Access Points) using underlying OS utilities and list related AP information.

- Supports Linux and Windows. 
- Output options include: formatted (default), csv and json


### <u>Install:</u>
pip install ap_scanner

or for source code:

git clone https://github.com/JavaWiz1/ap_scanner.git

### <u>Usage:</u>
```
ap_scanner [-h] [-i <iface>] [-r] [-j] [-c] [-v] [-t <filename>] [-s <filename>] [--nmcli] [--iwlist] [--iw] [--netsh]

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
```


### <u>Examples:</u>
Windows - trigger re-scan to get most current list of access points
```
> ap_scanner -r
---------------------------------------
Scan for wi-fi access points (Networks)
---------------------------------------
- Scanner netsh selected (Windows)
Rescan requested
- Autoconnect enabled for WiFiLAN1
- Disconnect to trigger re-scan of network
- Executing: netsh wlan disconnect
Scan for access points (networks)
- Executing: netsh wlan show network mode=bssid
- Process results of scan
- 9 APs discovered

SSID                      Auth            Encryption Mac Address       Signal Radio    Band    Channel
------------------------- --------------- ---------- ----------------- ------ -------- ------- -------
WiFiLAN1                  WPA2-Personal   CCMP       88:92:4e:26:05:e0   18%  802.11n  Unknown       1
 **hidden**               WPA2-Enterprise CCMP       dc:ec:69:0a:b0:8b   26%  802.11n  Unknown       1
                                                     dc:ec:69:0a:b0:8f   28%  802.11n  Unknown       1
                                                     88:9a:68:1d:3e:17   99%  802.11n  Unknown      11
                                                     88:9a:68:1d:3e:19   99%  802.11n  Unknown      11
                                                     88:9a:68:1d:3e:15   99%  802.11n  Unknown      11
SomeOtherWIFI             WPA2-Personal   CCMP       dc:ec:69:0a:b0:8a   30%  802.11n  Unknown       1
YetAnotherLAN             Open            None       f4:ce:a2:bc:bd:b1   66%  802.11n  Unknown       1
```

Linux - Use wlan2 connection for scan and use Network Manager (nmcli) for discovery
```
> ap_scanner -i wlan2 --nmcli
---------------------------------------
Scan for wi-fi access points (Networks)
---------------------------------------
- Scanner nmcli requested (Linux)
Scan for access points (networks)
- Process results of scan
- 8 APs discovered

SSID                      Auth            Encryption Mac Address       Signal Radio    Band    Channel
------------------------- --------------- ---------- ----------------- ------ -------- ------- -------
WiFiLAN1                  WPA2-Personal   CCMP       0C-9E-92-2C-BB-28  100%  Unknown  2.4 MHz       3
NETGEAR3x                 WPA2-Personal   CCMP       A0-41-A0-85-0F-D6  100%  Unknown  2.4 MHz       3
 **hidden**               WPA2-Personal   CCMP       88-9A-68-1D-3E-1A  100%  Unknown  2.4 MHz      11
 **hidden**               WPA2-Enterprise CCMP       88-9A-68-1D-3E-19  100%  Unknown  2.4 MHz      11
YetAnotherLAN             Open            None       F4-CE-A2-BC-BD-B1   47%  Unknown  2.4 MHz       1
```

### <u>Notes:</u>
- On windows, you can rescan (-r) and search for current networks
- You may save the outut of the underlying command into a file (-s)
- You can force which method searches for networks:
  - Linux:   nmcli, iw, iwlist
  - Windows: netsh


### <u>TODOs:</u>
- Identify Band (i.e 2.4MHz / 5Mhs) on Windows
- Radio identification for Linux
- Add Apple MAC capability
- Create unit tests