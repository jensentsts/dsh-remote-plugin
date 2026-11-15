/** Minimal sidecar facility for existing mocked-service regression tests; real facility coverage lives in messages-loopback. */
export function traceFixture() {
  const domains = new Map<string, unknown>()
  return {
    async open(spec: { name: string, tables: Record<string, { valueSchema: { parse(value: unknown): unknown } }> }) {
      const rows = new Map<string, unknown>()
      const table = { get: (key: string) => rows.get(key), async put(key: string, value: unknown) { rows.set(key, spec.tables.traces!.valueSchema.parse(value)) }, entries: () => rows.entries() }
      const domain = { table: () => table, async close() { domains.delete(spec.name) } }
      domains.set(spec.name, domain)
      return domain
    },
    get: (name: string) => domains.get(name),
  }
}
