# Treat the agent container as a trusted local source so rspamd doesn't
# discount its checks (otherwise some modules dampen scoring for traffic
# tagged as "local").
local_networks = "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";
