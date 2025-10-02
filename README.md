# Network outage checker

Small script to monitor network outage from LAN to WAN. Used as documentation to send to my ISP.

## Installation

Allow the python executable that runs `main.py` to open raw sockets. Do this to prevent having to call the script with sudo every time.

``` sh
sudo setcap cap_net_raw+ep /path/to/python/executable
```

## Usage

### Start ping

``` sh
uv run network_outage_monitor daemon --interval 5 --save ./test/ --ip 1.1.1.1
```

### Get report

``` sh
 uv run network_outage_monitor log --load ./test/
```
