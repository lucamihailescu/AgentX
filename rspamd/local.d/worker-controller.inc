# Controller worker — serves the learn endpoints (/learnspam, /learnham), the
# stats API, and the web UI on 11334. The scanner (worker-normal, 11333) does
# NOT handle learning, so per-user Bayes training must reach this worker.
#
# Bind on all interfaces so the agent container can reach it, and trust the
# internal docker network via secure_ip so the agent can train Bayes without a
# password. Rspamd's ports are only `expose`d on the compose network (never
# published to the host), so this stays internal to the stack.
#
# To require a password instead, drop `secure_ip`, set `password = "..."`
# here, and set AGENT_RSPAMD_PASSWORD to the same value.
bind_socket = "*:11334";
secure_ip = "127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16";
