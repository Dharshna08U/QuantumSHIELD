'use strict'

const fs = require('node:fs')
const crypto = require('node:crypto')

class FabricAdapter {
  constructor(env = process.env) {
    this.env = env
  }

  async _withContract(callback) {
    const required = ['FABRIC_MSP_ID', 'FABRIC_PEER_ENDPOINT', 'FABRIC_PEER_HOST_ALIAS',
      'FABRIC_TLS_CERT_PATH', 'FABRIC_CLIENT_CERT_PATH', 'FABRIC_PRIVATE_KEY_PATH',
      'FABRIC_CHANNEL', 'FABRIC_CHAINCODE']
    const missing = required.filter((key) => !this.env[key])
    if (missing.length) throw new Error('Fabric connection configuration is incomplete')

    const grpc = require('@grpc/grpc-js')
    const { connect, signers, hash } = require('@hyperledger/fabric-gateway')

    const tlsCert = fs.readFileSync(this.env.FABRIC_TLS_CERT_PATH)
    const client = new grpc.Client(
      this.env.FABRIC_PEER_ENDPOINT,
      grpc.credentials.createSsl(tlsCert),
      { 'grpc.ssl_target_name_override': this.env.FABRIC_PEER_HOST_ALIAS },
    )
    let gateway
    try {
      const identity = {
        mspId: this.env.FABRIC_MSP_ID,
        credentials: fs.readFileSync(this.env.FABRIC_CLIENT_CERT_PATH),
      }
      const privateKey = crypto.createPrivateKey(fs.readFileSync(this.env.FABRIC_PRIVATE_KEY_PATH))
      gateway = connect({ client, identity, signer: signers.newPrivateKeySigner(privateKey), hash: hash.sha256 })
      const network = gateway.getNetwork(this.env.FABRIC_CHANNEL)
      return await callback(network.getContract(this.env.FABRIC_CHAINCODE))
    } finally {
      if (gateway) gateway.close()
      client.close()
    }
  }

  async status() {
    try {
      await this._withContract((contract) => contract.evaluateTransaction('GetAllIncidents'))
      return { status: 'connected', provider: 'fabric' }
    } catch {
      return { status: 'unavailable', provider: 'fabric' }
    }
  }

  async recordIncident(record) {
    return this._withContract(async (contract) => {
      const result = await contract.submitTransaction(
        'CreateIncident', record.incident_id, JSON.stringify(record),
      )
      return JSON.parse(Buffer.from(result).toString('utf8'))
    })
  }

  async readIncident(incidentId) {
    return this._withContract(async (contract) => {
      const result = await contract.evaluateTransaction('ReadIncident', incidentId)
      return JSON.parse(Buffer.from(result).toString('utf8'))
    })
  }

  async hasIncident(incidentId) {
    try {
      await this.readIncident(incidentId)
      return true
    } catch (error) {
      if (/does not exist/i.test(error.message)) return false
      throw error
    }
  }

  async verifyIncident(incidentId, expectedHash) {
    const record = await this.readIncident(incidentId)
    return record.record_hash === expectedHash
  }
}

module.exports = { FabricAdapter }
