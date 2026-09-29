'use strict'

const { Contract } = require('fabric-contract-api')

class QuantumShieldContract extends Contract {
  async CreateIncident(ctx, incidentId, recordJson) {
    if (!incidentId || !recordJson) throw new Error('incidentId and recordJson are required')
    const key = `incident:${incidentId}`
    const existing = await ctx.stub.getState(key)
    if (existing && existing.length > 0) throw new Error(`Incident ${incidentId} already exists`)

    const record = JSON.parse(recordJson)
    if (record.incident_id !== incidentId || !record.record_hash) {
      throw new Error('Record ID and integrity hash are required')
    }
    const transactionId = ctx.stub.getTxID()
    const fabricTime = ctx.stub.getTxTimestamp()
    const ledgerTimestamp = new Date(
      Number(fabricTime.seconds) * 1000 + Math.floor(Number(fabricTime.nanos || 0) / 1e6),
    ).toISOString()
    const stored = {
      incident_id: incidentId,
      timestamp: record.timestamp,
      source: record.source,
      incident_type: record.incident_type,
      severity: record.severity,
      classification: record.classification,
      confidence: record.confidence,
      recommended_action: record.recommended_action,
      healing_status: record.healing_status,
      record_hash: record.record_hash,
      signature_algorithm: record.signature_algorithm,
      signature_verification_status: record.signature_verification_status,
      kem_algorithm: record.kem_algorithm,
      encryption_status: record.encryption_status,
      blockchain_tx_id: transactionId,
      blockchain_timestamp: ledgerTimestamp,
    }
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(stored)))
    ctx.stub.setEvent('IncidentRecorded', Buffer.from(JSON.stringify({ incident_id: incidentId })))
    return JSON.stringify(stored)
  }

  async ReadIncident(ctx, incidentId) {
    const bytes = await ctx.stub.getState(`incident:${incidentId}`)
    if (!bytes || bytes.length === 0) throw new Error(`Incident ${incidentId} does not exist`)
    return bytes.toString('utf8')
  }

  async GetAllIncidents(ctx) {
    const iterator = await ctx.stub.getStateByRange('incident:', 'incident;')
    const records = []
    try {
      while (true) {
        const result = await iterator.next()
        if (result.value && result.value.value.length > 0) {
          records.push(JSON.parse(result.value.value.toString('utf8')))
        }
        if (result.done) break
      }
    } finally {
      await iterator.close()
    }
    return JSON.stringify(records)
  }
}

module.exports = QuantumShieldContract
