// RCA186 storage-only candidate. No external access, auth or provider writes.
import { DurableObject } from "cloudflare:workers";
const ZERO = "0".repeat(64);
function validDigest(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
export class Checkpoint extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS checkpoint (generation INTEGER PRIMARY KEY, digest TEXT NOT NULL)");
    this.sql.exec("INSERT OR IGNORE INTO checkpoint VALUES (0, ?)", ZERO);
  }
  async current() {
    return this.sql.exec("SELECT generation, digest FROM checkpoint ORDER BY generation DESC LIMIT 1").one();
  }
  async advance(expected, previous, next) {
    if (!Number.isSafeInteger(expected) || expected < 0 || expected >= Number.MAX_SAFE_INTEGER ||
        !validDigest(previous) || !validDigest(next) || previous === next) {
      return { result: "INVALID" };
    }
    return this.ctx.storage.transactionSync(() => {
      const current = this.sql.exec("SELECT generation, digest FROM checkpoint ORDER BY generation DESC LIMIT 1").one();
      if (current.generation !== expected || current.digest !== previous) return { result: "CONFLICT" };
      this.sql.exec("INSERT INTO checkpoint VALUES (?, ?)", expected + 1, next);
      return { result: "COMMITTED", generation: expected + 1, digest: next };
    });
  }
}
export default {
  async fetch() {
    return new Response("NOT_ENABLED", {status:403, headers:{"Cache-Control":"no-store"}});
  }
};
