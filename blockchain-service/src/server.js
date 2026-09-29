'use strict'

const express = require('express')
const crypto = require('node:crypto')
const { FabricAdapter } = require('./fabricAdapter')

const app = express()
const adapter = new FabricAdapter()
app.use(express.json({ limit: '64kb' }))

app.get('/health', (_req, res) => res.json({ status: 'ok' }))
app.use('/v1', (req, res, next) => {
  const expected = process.env.BLOCKCHAIN_API_TOKEN || ''
  const supplied = (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
  const expectedBytes = Buffer.from(expected)
  const suppliedBytes = Buffer.from(supplied)
  const valid = expectedBytes.length > 0 && expectedBytes.length === suppliedBytes.length &&
    crypto.timingSafeEqual(expectedBytes, suppliedBytes)
  if (!valid) return res.status(401).json({ error: { code: 'unauthorized', message: 'Invalid service credentials' } })
  return next()
})
app.get('/v1/status', async (_req, res) => res.json(await adapter.status()))

app.post('/v1/incidents', async (req, res) => {
  const { incident_id: incidentId, record_hash: recordHash, metadata } = req.body || {}
  if (typeof incidentId !== 'string' || incidentId.length < 1 || incidentId.length > 128 ||
      typeof recordHash !== 'string' || !/^[a-f0-9]{64}$/i.test(recordHash) ||
      !metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return res.status(422).json({ error: { code: 'invalid_request', message: 'Invalid ledger record' } })
  }
  try {
    const record = await adapter.recordIncident({ incident_id: incidentId, record_hash: recordHash, ...metadata })
    return res.status(201).json({
      provider: 'fabric',
      transaction_id: record.blockchain_tx_id,
      timestamp: record.blockchain_timestamp,
    })
  } catch (error) {
    const duplicate = /already exists/i.test(error.message)
    return res.status(duplicate ? 409 : 503).json({
      error: { code: duplicate ? 'conflict' : 'fabric_unavailable', message: duplicate ? 'Incident already exists' : 'Fabric operation failed' },
    })
  }
})

app.get('/v1/incidents/:incidentId', async (req, res) => {
  try {
    const record = await adapter.readIncident(req.params.incidentId)
    return res.json({
      provider: 'fabric',
      incident_id: record.incident_id,
      record_hash: record.record_hash,
      timestamp: record.blockchain_timestamp,
      transaction_id: record.blockchain_tx_id,
      metadata: record,
    })
  } catch (error) {
    const missing = /does not exist/i.test(error.message)
    return res.status(missing ? 404 : 503).json({
      error: { code: missing ? 'not_found' : 'fabric_unavailable', message: missing ? 'Incident not found' : 'Fabric operation failed' },
    })
  }
})

app.get('/v1/incidents/:incidentId/exists', async (req, res) => {
  try {
    return res.json({ exists: await adapter.hasIncident(req.params.incidentId), provider: 'fabric' })
  } catch {
    return res.status(503).json({ error: { code: 'fabric_unavailable', message: 'Fabric operation failed' } })
  }
})

app.post('/v1/incidents/:incidentId/verify', async (req, res) => {
  const expectedHash = req.body?.record_hash
  if (typeof expectedHash !== 'string' || !/^[a-f0-9]{64}$/i.test(expectedHash)) {
    return res.status(422).json({ error: { code: 'invalid_request', message: 'Invalid record hash' } })
  }
  try {
    const verified = await adapter.verifyIncident(req.params.incidentId, expectedHash)
    return res.json({ verified, provider: 'fabric' })
  } catch (error) {
    const missing = /does not exist/i.test(error.message)
    return res.status(missing ? 404 : 503).json({
      error: { code: missing ? 'not_found' : 'fabric_unavailable', message: missing ? 'Incident not found' : 'Fabric operation failed' },
    })
  }
})

app.use((error, _req, res, _next) => {
  const tooLarge = error.type === 'entity.too.large'
  return res.status(tooLarge ? 413 : 400).json({
    error: { code: tooLarge ? 'payload_too_large' : 'invalid_request', message: tooLarge ? 'Request body exceeds limit' : 'Invalid request body' },
  })
})

if (require.main === module) {
  const port = Number(process.env.PORT || 4000)
  app.listen(port, '0.0.0.0', () => console.log(`Blockchain adapter listening on ${port}`))
}

module.exports = { app }
