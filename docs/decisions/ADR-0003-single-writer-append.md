# ADR-0003: Serializing chain appends

**Status:** Accepted

## Context

A hash chain requires a total order. Two concurrent appends must not read the same `prev_hash` or
claim the same `seq`. This must hold even if the service runs as multiple instances.

## Decision

Every append is one transaction that begins with `SELECT ... FOR UPDATE` on the single
`chain_head` row (`ChainHeadRepository.lockHead()`), then computes `seq = last_seq + 1`, inserts
the row, and updates `chain_head`. The database row lock is the serialization point and works
across instances sharing the database.

## Alternatives considered

| Option | Why not (for now) |
|---|---|
| Application-level `ReentrantLock` | Only correct for a single instance. |
| DB auto-increment `seq` + tolerate out-of-order hashing | Can't compute `record_hash` without the predecessor; reintroduces a race on `prev_hash`. |
| Append to an in-memory queue drained by a single background writer | Adds a durability gap (events acknowledged but not yet chained) and a component to operate. |
| Per-stream chains (shard by `resourceType`/tenant), each independently serialized | This is the intended **scale path**, not needed at current scope. |

## Consequences

- Write throughput is bounded by one writer per chain. For an audit log this is acceptable;
  measured append latency is dominated by hashing + one insert.
- On H2 file mode the lock is a local row lock; on Postgres it is `SELECT FOR UPDATE` /
  advisory-lock territory — same code.
- If/when throughput matters: introduce multiple named chains, each with its own `chain_head`
  row and genesis, and verify them independently. The API and hashing are unchanged.
