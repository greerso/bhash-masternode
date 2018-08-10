
B-Hash Masternode Setup Guided Setup
=========================================

Make sure that your terminal window is at least 80x25.  Then copy paste the following command, it will walk you through the rest step-by-step:

```
sudo bash -c "$(curl -sSL https://raw.githubusercontent.com/greerso/bhash-masternode/master/install.sh)"
```


If you ran this script previously and the service to start/stop the daemon isn't working run this
command to fix it:
```
sudo sed -ri "s|(^(.{0,2})ExecStart=/usr/local/bin/bhashd stop)(
*)?(.*)|ExecStop=/usr/local/bin/bhashd stop|1" /etc/systemd/system/bhashd.service
```
