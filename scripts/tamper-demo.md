# Tamper demo

Proves the whole point of the service: a modification made directly in the datastore, bypassing
the API entirely, is detected by `GET /audit/verify`.

## 1. Start the service (dev profile enables the H2 console)

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

## 2. Write a few events

```bash
BASE=http://localhost:8080
W='X-Api-Key: dev-writer-key'

curl -s -X POST $BASE/audit/events -H "$W" -H 'Content-Type: application/json' \
  -d '{"eventType":"USER_LOGIN","actorId":"alice","resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","payload":{"ip":"10.0.0.1"}}'
curl -s -X POST $BASE/audit/events -H "$W" -H 'Content-Type: application/json' \
  -d '{"eventType":"ACCOUNT_VIEWED","actorId":"alice","resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","payload":{"channel":"web"}}'
curl -s -X POST $BASE/audit/events -H "$W" -H 'Content-Type: application/json' \
  -d '{"eventType":"RECORD_UPDATED","actorId":"bob","resourceType":"CLIENT_ACCOUNT","resourceId":"acct-2","payload":{"field":"email"}}'
```

## 3. Verify — expect `intact: true`

```bash
curl -s "$BASE/audit/verify" -H "$W"
# {"intact":true,"recordsChecked":3,...,"firstInconsistency":null}
```

## 4. Tamper directly in the datastore

Either open `http://localhost:8080/h2-console` (JDBC URL `jdbc:h2:file:./data/auditdb`, user `sa`,
empty password) and run the SQL, or use the bundled H2 shell from a second terminal:

```bash
H2JAR=$(find ~/.m2 -name 'h2-*.jar' | head -1)
java -cp "$H2JAR" org.h2.tools.Shell \
  -url "jdbc:h2:file:./data/auditdb;AUTO_SERVER=TRUE" -user sa -password "" \
  -sql "UPDATE audit_event SET actor_id='mallory' WHERE seq=2;"
```

## 5. Verify again — expect `intact: false`

```bash
curl -s "$BASE/audit/verify" -H "$W"
# {"intact":false,"recordsChecked":2,...,
#  "firstInconsistency":{"seq":2,"violationType":"CONTENT_HASH_MISMATCH",...}}
```

## Other tamper cases to try

| SQL | Detected as |
|---|---|
| `UPDATE audit_event SET payload_json='{"ip":"9.9.9.9"}' WHERE seq=1` | `LEAF_COMMITMENT_MISMATCH` at seq 1 |
| `DELETE FROM audit_event WHERE seq=2` | `SEQUENCE_GAP` |
| `UPDATE audit_event SET record_hash=repeat('0',64) WHERE seq=2` | `RECORD_HASH_MISMATCH` at seq 2 |
| `UPDATE audit_event SET prev_hash=repeat('0',64) WHERE seq=2` | `PREV_HASH_MISMATCH` at seq 2 |

## Redaction does NOT trip verification

```bash
curl -s -X POST "$BASE/audit/events/<eventId>/redactions" -H 'X-Api-Key: dev-admin-key' \
  -H 'Content-Type: application/json' -d '{"fieldPaths":["/channel"],"reason":"demo","redactedBy":"me"}'
curl -s "$BASE/audit/verify" -H "$W"   # still intact:true
```
