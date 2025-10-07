# Network outage monitor

Small script to monitor network outage from LAN to WAN. Used as documentation to send to my ISP.

## Setup

```sh
git clone --depth=1 https://github.com/fslaktern/network-outage-monitor.git
cd network-outage-monitor
```


> [!NOTE]
> You may run the program without root by giving the python executable permission to open raw sockets.
>
> ``` sh
> # Copy the python executable to keep global environment clean
> cp --dereference $(which python3) ./python3-cap-net-raw
>
> sudo setcap cap_net_raw+ep ./python3-cap-net-raw
> ```


## Usage

### Start ping

``` sh
uv run network_outage_monitor daemon --interval 5 --save ./cloudflare --ip 1.1.1.1

# Send updates to a Discord channel
uv run network_outage_monitor daemon --interval 5 --save ./google --ip google.com --discord-webhook https://discordapp.com/api/webhooks/<channel_id>/<secret>
```

### Get report

``` sh
uv run network_outage_monitor log --load ./cloudflare
```
