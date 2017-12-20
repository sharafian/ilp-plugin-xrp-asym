const crypto = require('crypto')
const addressCodec = require('ripple-address-codec')
const { RippleAPI } = require('ripple-lib')
const { URL } = require('url')
const BtpPacket = require('btp-packet')
const BigNumber = require('bignumber.js')
const WebSocket = require('ws')
const assert = require('assert')
const debug = require('debug')('ilp-plugin-xrp-stateless')
const AbstractBtpPlugin = require('./btp-plugin')
const base64url = require('base64url')
const INFO_REQUEST_ALL = 2
const OUTGOING_CHANNEL_DEFAULT_AMOUNT_XRP = '10' // TODO: something lower?
const MIN_SETTLE_DELAY = 3600
const nacl = require('tweetnacl')
const bignum = require('bignum')

function hmac (key, message) {
  const h = crypto.createHmac('sha256', key)
  h.update(message)
  return h.digest()
}

const computeChannelId = (src, dest, sequence) => {
  const preimage = Buffer.concat([
    Buffer.from('\0x', 'ascii'),
    Buffer.from(addressCodec.decodeAccountID(src)),
    Buffer.from(addressCodec.decodeAccountID(dest)),
    bignum(sequence).toBuffer({ endian: 'big', size: 4 })
  ])

  return crypto.createHash('sha512')
    .update(preimage)
    .digest()
    .slice(0, 32) // first half sha512
    .toString('hex')
    .toUpperCase()
}

const encodeClaim = (amount, id) => Buffer.concat([
  Buffer.from('CLM\0'),
  Buffer.from(id, 'hex'),
  bignum(amount).toBuffer({
    endian: 'big',
    size: 8
  })
])

const randomTag = () => bignum.fromBuffer(crypto.randomBytes(4), {
  endian: 'big',
  size: 4
}).toNumber()

async function _requestId () {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(4, (err, buf) => {
      if (err) reject(err)
      resolve(buf.readUInt32BE(0))
    })
  })
}

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

  async _createOutgoingChannel () {
    debug('creating outgoing channel')
    const txTag = randomTag()
    const tx = await this._api.preparePaymentChannelCreate(this._address, {
      amount: OUTGOING_CHANNEL_DEFAULT_AMOUNT_XRP,
      destination: this._peerAddress,
      settleDelay: MIN_SETTLE_DELAY,
      publicKey: 'ED' + Buffer.from(this._keyPair.publicKey).toString('hex').toUpperCase(),
      sourceTag: txTag
    })

    debug('signing transaction')
    const signedTx = this._api.sign(tx.txJSON, this._secret)
    const result = await this._api.submit(signedTx.signedTransaction)

    debug('submitted outgoing channel tx to validator')
    if (result.resultCode !== 'tesSUCCESS') {
      const message = 'Error creating the payment channel: ' + result.resultCode + ' ' + result.resultMessage
      debug(message)
      return
    }

    // TODO: make a generic version of the code that submits these things
    debug('waiting for transaction to be added to the ledger')
    return new Promise((resolve) => {
      const handleTransaction = (ev) => {
        if (ev.transaction.SourceTag !== txTag) return
        if (ev.transaction.Account !== this._address) return

        debug('transaction complete')
        const channel = computeChannelId(
          ev.transaction.Account,
          ev.transaction.Destination,
          ev.transaction.Sequence)

        setImmediate(() => this._api.connection
          .removeListener('transaction', handleTransaction))
        resolve(channel)
      }

      this._api.connection.on('transaction', handleTransaction)
    })
  }

  async connect () {
    if (this._ws) return

    await this._api.connect()
    await this._api.connection.request({
      command: 'subscribe',
      accounts: [ this._address ]
    })

    const parsedServer = new URL(this._server)
    const host = parsedServer.host // TODO: include path
    const secret = parsedServer.password
    const ws = this._ws = new WebSocket('ws://' + host) // TODO: wss
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

    return new Promise((resolve) => {
      this._ws.on('open', async () => {
        debug('connected to server')

        await this._call(null, {
          type: BtpPacket.TYPE_MESSAGE,
          requestId: await _requestId(),
          data: { protocolData }
        })

        const infoResponse = await this._call(null, {
          type: BtpPacket.TYPE_MESSAGE,
          requestId: await _requestId(),
          data: { protocolData: [{
            protocolName: 'info',
            contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
            data: Buffer.from([ INFO_REQUEST_ALL ])
          }] }
        })

        // TODO: do the processes of channel establishment and client-channel
        // establishment occur in here automatically (in the case that no channel
        // exists) or do they happen in a separate script?

        const info = JSON.parse(infoResponse.protocolData[0].data.toString())
        debug('got info:', info)

        this._prefix = info.prefix
        this._channel = info.channel
        this._clientChannel = info.clientChannel
        this._peerAddress = info.address
        this._keyPair = nacl.sign.keyPair
          .fromSeed(hmac(
            this._secret,
            'ilp-plugin-xrp-stateless' + this._peerAddress
          ))

        // TODO: should this occur as part of info or should the connector send us a
        // separate message to inform us that they have a channel to us?
        if (this._clientChannel) {
          // TODO: validate all these payment channel details
          this._paychan = await this._api.getPaymentChannel(this._clientChannel)
          // TODO: also load best claim from the crash-cache
          this._bestClaim = {
            amount: xrpToDrops(this._paychan.balance)
          }
        }

        // TODO: is this an attack vector, if not telling the plugin about their channel
        // causes them to open another channel?
        if (!this._channel) {
          this._channel = await this._createOutgoingChannel()
          // TODO: can we call 'channel' and 'fund_channel' here at the same time?
          await this._call(null, {
            type: BtpPacket.TYPE_MESSAGE,
            requestId: await _requestId(),
            data: { protocolData: [{
              protocolName: 'channel',
              contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
              data: Buffer.from(this._channel, 'hex')
            }] }
          })
        }

        // finished the connect process
        resolve()
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
    })
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

    debug('got outgoing fulfill with primary protocol', primary && primary.protocolName)
    if (primary.protocolName === 'claim') {
      const lastClaim = JSON.parse(primary.data.toString())
      const encodedClaim = encodeClaim(lastClaim.amount, this._channel)

      debug('given last claim of', lastClaim)

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
      } else {
        debug('signing first claim')
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
    console.log('SENDING', btpPacket, 'to', to)
    try { 
      await new Promise(resolve => this._ws.send(BtpPacket.serialize(btpPacket), resolve))
    } catch (e) {
      debug('unable to send btp message to client: ' + errorInfo, 'btp packet:', JSON.stringify(btpPacket))
    }
  }
}

module.exports = Plugin
