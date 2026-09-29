const { test } = require('node:test')
const assert = require('node:assert/strict')
const { FabricAdapter } = require('../src/fabricAdapter')

test('reports unavailable instead of fabricating a ledger connection', async () => {
  const status = await new FabricAdapter().status()
  assert.equal(status.status, 'unavailable')
})

test('does not accept writes without an adapter', async () => {
  await assert.rejects(() => new FabricAdapter().recordIncident(), /configuration is incomplete/)
})
