# Dnstap Plugin for Graylog

**Required Graylog version:** 2.0 and later


The plugin provides an input for the [Dnstap protocol](http://dnstap.info/) in Graylog.
It can be used to receive data from logs provided by [`fstrm_capture`](https://github.com/farsightsec/fstrm)
(e.g. `socat FILE:/var/log/unbound/unbound.dnstap TCP:graylog-server:6000`)
or to communicate with DNS server directly
(e.g. `socat UNIX-LISTEN:/var/run/unbound/dnstap.sock,user=unbound,unlink-early,fork TCP:graylog-server:6000,nodelay,pf=ip4`).

Installation
------------

[Download the plugin](https://github.com/sega-yarkin/graylog-plugin-dnstap/releases)
and place the `.jar` file in your Graylog plugin directory. The plugin directory
is the `plugins/` folder relative from your `graylog-server` directory by default
and can be configured in your `graylog.conf` file.

Restart `graylog-server` and you are done.
