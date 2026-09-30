# Cyber Sentinel integration

Sentinel Engram reads from Cyber Sentinel and never writes to it. This page lists every change it makes on the Cyber Sentinel side and how to move them into the Cyber Sentinel repository.

## What playbook 07 creates on a Cyber Sentinel host

| Object | Where | Purpose |
|---|---|---|
| system user `engram-tunnel` | host OS | SSH local forward only — `restrict,port-forwarding,permitopen="10.10.10.9:5432",from="<engram host IP>"`, shell `/usr/sbin/nologin` |
| role `engram_reader` | Postgres | `LOGIN`, `NOINHERIT`, `CONNECTION LIMIT 3`, `default_transaction_read_only=on`, `statement_timeout=300s` |
| schema `engram_export` | Postgres | owned by `postgres`; `engram_reader` has `USAGE` only |
| view `engram_export.v_verdicts` | Postgres | one row per `threat_indicators` row, joined with the DNS query, AI verdict, threat level and providers |
| function `engram_export.fn_dns_seen(timestamp)` | Postgres | `SECURITY DEFINER`, aggregated `(domain, response_ip)` pairs since a timestamp; the time filter runs before aggregation, so `dns_queries` partitions are pruned |

Nothing is created in, altered in or granted on `cyber_sentinel` or `cyber_sentinel_ai`. The reader cannot query any Cyber Sentinel table directly.

## Why an SSH tunnel instead of publishing port 5432

- `postgres_db` has no published port in `docker-compose-cyber-sentinel.yml`.
- A Docker-published port would bypass UFW, because Docker writes its own iptables rules. Limiting it to the ZimaBoard would need a `DOCKER-USER` rule.
- The tunnel exists only while a sync run is in progress. It needs no change to the Cyber Sentinel compose file or firewall, and it encrypts the connection.

## Making it permanent in the Cyber Sentinel repository

The Cyber Sentinel dev VM is restored from backup before every dev deploy, which removes the schema and the tunnel user. Until the steps below are done, run `07_cs_source_access.yml --limit cs_dev_vm` after every Cyber Sentinel dev deploy.

1. Copy `config/cyber-sentinel/db_engram_export.sql` to `config/postgres/` in Cyber Sentinel.
2. Add a render + execute step for it to `04_3b_db_postgres.yml`, after `db_ai_pipeline.sql`. The template needs `cs_pg_reader_user` and `vault_cs_pg_reader_password` in Cyber Sentinel's vars.
3. Move the `engram-tunnel` user tasks (`[07.1.1]`–`[07.1.5]`) into a Cyber Sentinel playbook, or keep running playbook 07 for that part only.

## Pi-hole Local DNS

Add these records in Cyber Sentinel (`config/dns/dnsmasq.d` or the Pi-hole UI):

```
<ZimaBoard IP>  cortex.engram.prod
<ZimaBoard IP>  neo4j.engram.prod
<dev VM IP>     cortex.engram.local
<dev VM IP>     neo4j.engram.local
```

n8n on the Pi reaches the Cortex API through `https://cortex.engram.prod`.
