# OSPF Watcher Release Notes v3.3.0

Requires Topolograph v2.73. The watcher image is unchanged; this release changes
the log-shipping configuration shipped in this repository.

## Changes

**Events are sent to Topolograph with a login**
Logstash and Fluent Bit send every live event with the Topolograph login from
`.env`: `TOPOLOGRAPH_WEB_API_USERNAME_EMAIL` and `TOPOLOGRAPH_WEB_API_PASSWORD`.
Topolograph v2.73 rejects an event without them with 401.

**Topolograph stores the events**
Logstash no longer writes events to MongoDB. Topolograph stores every event it
receives and shows it on the Monitoring page of the graph. `MONGODB_*` and
`EXPORT_TO_MONGO_BOOL` are removed from the compose files and `.env.template`.

## Upgrade

1. Set `TOPOLOGRAPH_WEB_API_USERNAME_EMAIL` and `TOPOLOGRAPH_WEB_API_PASSWORD` in `.env`.
2. Pull the repository and rebuild the Logstash image: `docker compose up -d --build`.
