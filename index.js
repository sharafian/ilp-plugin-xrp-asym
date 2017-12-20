const crypto = require('crypto')
const { RippleAPI } = require('ripple-lib')
const BtpPacket = require('btp-packet')
const BigNumber = require('bignumber.js')
const WebSocket = require('ws')
const assert = require('assert')
const debug = require('debug')('ilp-plugin-mini-accounts')
const AbstractBtpPlugin = require('./btp-plugin')
const base64url = require('base64url')
const INFO_REQUEST_ALL = 2

const encodeClaim = (amount, id) => Buffer.concat([
  Buffer.from('CLM\0'),
  Buffer.from(id, 'hex'),
  bignum(amount).toBuffer({
    endian: 'big',
    size: 8
  })
])

class Plugin extends AbstractBtpPlugin {
  constructor (opts) {
    super()
    this._currencyScale = 6
    this._server = opts.server
    this._unsecured = new BigNumber(0)
    this._bandwidth = 200

    // TODO: should use channel secret or xrp secret
    this._secret = opts.secret
    this._address = opts.address // TODO: can default from secret
    this._xrpServer = opts.xrpServer // TODO: default here
    this._api = new RippleAPI({ server: this._xrpServer })

    this._log = opts._log || console
    this._ws = null

    this.on('incoming_reject', this._handleIncomingReject.bind(this))
  }

  async connect () {
    if (this._ws) return

    await this._api.connect()

    const parsedServer = new URL(this._server)
    const host = parsedServer.host // TODO: include path
    const secret = parsedServer.password
    const ws = this._ws = new WebSocket(host)
    const protocolData = [{
      protocolName: 'auth',
      contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
      data: Buffer.from([])
    }, {
      protocolName: 'auth_username',
      contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
      data: Buffer.from('', 'utf8')
    }, {
      protocolName: 'auth_token',
      contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
      data: Buffer.from(secret, 'utf8')
    }]

    this._ws.on('open', async () => {
      debug('connected to server')

      await this._call(null, {
        type: BtpPacket.TYPE_MESSAGE,
        requestId,
        data: { protocolData }
      })

      const info = await this._call(null, {
        type: BtpPacket.TYPE_MESSAGE,
        requestId,
        data: { protocolData: [{
          protocolName: 'info',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: Buffer.from([ INFO_REQUEST_ALL ])
        }] }
      })

      // TODO: do the processes of channel establishment and client-channel
      // establishment occur in here automatically (in the case that no channel
      // exists) or do they happen in a separate script?

      this._prefix = info.prefix
      this._channel = info.channel
      this._clientChannel = info.clientChannel
      this._peerAddress = info.address
      this._keyPair = nacl.sign.keyPair
        .fromSeed(hmac(
          this._secret,
          'ilp-plugin-xrp-stateless' + this._peerAddress
        ))

      this._paychan = await this._api.getPaymentChannel(this._clientChannel)
      // TODO: also load best claim from the crash-cache
      this._bestClaim = {
        amount: xrpToDrops(this._paychan.balance)
      }
    })

    this._ws.on('message', (binaryMessage) => {
      let btpPacket
      try {
        btpPacket = BtpPacket.deserialize(binaryMessage)
      } catch (err) {
        wsIncoming.close()
      }
      try {
        if (btpPacket.type === BtpPacket.TYPE_PREPARE) {
          this._handleIncomingBtpPrepare(btpPacket)
        }
        debug('packet is authorized, forwarding to host')
        this._handleIncomingBtpPacket(this._prefix, btpPacket)
      } catch (err) {
        debug('btp packet not accepted', err)
        const errorResponse = BtpPacket.serializeError({
          code: 'F00',
          name: 'NotAcceptedError',
          triggeredAt: new Date().toISOString(),
          data: err.message
        }, btpPacket.requestId, [])
        wsIncoming.send(errorResponse)
      }
    })

    return null
  }

  disconnect () {
    if (this._ws) {
      return new Promise(resolve => {
        this._ws.close(resolve)
        this._ws = null
      })
    }
  }

  isConnected () {
    return !!this._ws
  }

  _handleIncomingBtpPrepare (btpPacket) {
    const prepare = btpPacket.data
    const newUnsecured = this._unsecured.add(prepare.amount)

    if (newUnsecured.greaterThan(this._bandwidth)) {
      throw new Error('Insufficient bandwidth, have: ' + this._bandwidth + ' need: ' + newUnsecured)
    }
  }

  _handleOutgoingFulfill (transfer, btpData) {
    const primary = btpData.protocolData[0]

    if (primary.protocolName === 'claim') {
      const lastClaim = JSON.parse(primary.data.toString())
      const encodedClaim = encodeClaim(lastClaim.amount, this._channel)

      // If they say we haven't sent them anything yet, it doesn't matter
      // whether they possess a valid claim to say that.
      if (lastClaim.amount !== '0') {
        try {
          nacl.sign.detached.verify(
            encodedClaim,
            Buffer.from(lastClaim.signature, 'hex'),
            this._keyPair.publicKey
          )
        } catch (err) {
          debug('invalid claim signature for', amount)
          return
        }
      }

      const amount = new BigNumber(lastClaim.amount).add(transfer.amount).toString()
      const newClaimEncoded = encodeClaim(amount, this._channel)
      const signature = Buffer
        .from(nacl.sign.detached(newClaimEncoded, this._keyPair.secretKey))
        .toString('hex')
        .toUpperCase()

      return [{
        protocolName: 'claim',
        contentType: BtpPacket.MIME_APPLICATION_JSON,
        data: Buffer.from(JSON.stringify({ amount, signature }))
      }]
    }
  }

  _handleIncomingFulfillResponse (transfer, response) {
    const primary = response.protocolData[0]

    if (primary.protocolName === 'claim') {
      const nextAmount = this._bestClaim.amount.add(transfer.amount)
      const { amount, signature } = JSON.parse(primary.data.toString())
      const encodedClaim = encodeClaim(amount, this._clientChannel)

      if (nextAmount.notEquals(amount)) {
        debug('expected claim for', nextAmount.toString(), 'got', amount)
        return
      }

      try {
        nacl.sign.detached.verify(
          encodedClaim,
          Buffer.from(signature, 'hex'),
          Buffer.from(this._paychan.publicKey.substring(2), 'hex')
        )
      } catch (err) {
        debug('invalid claim signature for', amount)
        return
      }

      this._unsecured = this._unsecured.sub(transfer.amount)
      this._bestClaim = { amount, signature }
    }
  }

  _handleIncomingReject (transfer) {
    this._unsecured = this._unsecured.sub(transfer.amount)
  }

  getAccount () {
    return this._prefix + 'server'
  }

  getInfo () {
    return {
      prefix: this._prefix,
      connectors: [],
      currencyScale: this._currencyScale
    }
  }

  async _handleOutgoingBtpPacket (to, btpPacket) {
    try { 
      await new Promise(resolve => this._ws.send(BtpPacket.serialize(btpPacket), resolve))
    } catch (e) {
      debug('unable to send btp message to client: ' + errorInfo, 'btp packet:', JSON.stringify(btpPacket))
    }
  }
}

module.exports = Plugin
