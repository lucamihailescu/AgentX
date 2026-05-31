# Treat the agent container as a trusted local source so rspamd doesn't
# discount its checks (otherwise some modules dampen scoring for traffic
# tagged as "local").
local_networks = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";

# Point DNS (incl. DNSBL lookups) at the bundled Unbound recursive resolver
# instead of the container's default (Docker embedded DNS → public forwarder),
# which blocklist providers rate-limit/refuse — the cause of the
# "rbl.lua: query timed out" spam. master-slave keeps a public resolver as a
# low-weight fallback if unbound is down. The hostname form needs rspamd >= 3.14.
dns {
  nameserver = "master-slave:unbound:53:10,1.1.1.1:53:1";
  timeout = 1s;
  sockets = 16;
  retransmits = 5;
}
