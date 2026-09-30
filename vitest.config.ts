import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts", "server/src/**/*.test.ts", "src/**/*.test.ts"],
    environment: "node",
    // Every test file gets a throwaway ~/.contextengine: no test may touch the real store or
    // the real audit log (30 fake community.sync_error rows landed there on 2026-09-05).
    setupFiles: ["./src/test-setup.ts"],
    globals: true,
    // 30 s, not the 10 s set when the suite had 25 tests (36ad8f0). On 2026-09-30 it had 917, fourteen
    // files append thousands of audit records per test, and under Node 20 (the owner's runtime) a full
    // parallel run on his Mac took them to 9 to 16 s: two runs in a row failed on the limit, each time
    // on the next heaviest tests. A test that hangs still fails, after 30 s.
    testTimeout: 30_000,
  },
});
