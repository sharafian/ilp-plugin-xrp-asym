const { deriveAddress, deriveKeypair } = require('ripple-keypairs')
const { RippleAPI } = require('ripple-lib')
const { URL } = require('url')
const BtpPacket = require('btp-packet')
const BigNumber = require('bignumber.js')
const WebSocket = require('ws')
const assert = require('assert')
const debug = require('debug')('ilp-plugin-xrp-stateless')
const AbstractBtpPlugin = require('./btp-plugin')
const base64url = require('base64url')
const nacl = require('tweetnacl')
const util = require('./util')
const OUTGOING_CHANNEL_DEFAULT_AMOUNT_XRP = '10' // TODO: something lower?
const { ChannelWatcher } = require('ilp-plugin-xrp-paychan-shared')

class Plugin extends AbstractBtpPlugin {
  constructor (opts) {
    super()
    this._currencyScale = 6
    this._server = opts.server

    if (!opts.server || !opts.secret) {
      throw new Error('opts.server and opts.secret must be specified')
    }

    // TODO: should use channel secret or xrp secret
    this._secret = opts.secret
    this._address = opts.address || deriveAddress(deriveKeypair(this._secret).publicKey)
    this._xrpServer = opts.xrpServer

    // make sure two funds don't happen at once
    this._funding = false

    // optional
    this._store = opts.store
    this._writeQueue = Promise.resolve()

    this._log = opts._log || console
    this._ws = null

    // this.on('incoming_reject', this._handleIncomingReject.bind(this))
  }

  async _createOutgoingChannel () {
    debug('creating outgoing channel')
    const txTag = util.randomTag()
    const tx = await this._api.preparePaymentChannelCreate(this._address, {
      amount: OUTGOING_CHANNEL_DEFAULT_AMOUNT_XRP,
      destination: this._peerAddress,
      settleDelay: util.MIN_SETTLE_DELAY,
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
        const channel = util.computeChannelId(
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

    return new Promise((resolve, reject) => {
      this._ws.on('open', async () => {
        debug('connected to server')

        await this._call(null, {
          type: BtpPacket.TYPE_MESSAGE,
          requestId: await util._requestId(),
          data: { protocolData }
        })

        const infoResponse = await this._call(null, {
          type: BtpPacket.TYPE_MESSAGE,
          requestId: await util._requestId(),
          data: { protocolData: [{
            protocolName: 'info',
            contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
            data: Buffer.from([ util.INFO_REQUEST_ALL ])
          }] }
        })

        // TODO: do the processes of channel establishment and client-channel
        // establishment occur in here automatically (in the case that no channel
        // exists) or do they happen in a separate script?

        const info = JSON.parse(infoResponse.protocolData[0].data.toString())
        debug('got info:', info)

        this._account = info.account
        this._prefix = info.prefix
        this._channel = info.channel
        this._clientChannel = info.clientChannel
        this._peerAddress = info.address
        this._keyPair = nacl.sign.keyPair
          .fromSeed(util.hmac(
            this._secret,
            'ilp-plugin-xrp-stateless' + this._peerAddress
          ))

        if (!this._xrpServer) {
          this._xrpServer = this._account.startsWith('test.')
            ? 'wss://s.altnet.rippletest.net:51233'
            : 's1.ripple.com'
        }

        this._api = new RippleAPI({ server: this._xrpServer })
        await this._api.connect()
        await this._api.connection.request({
          command: 'subscribe',
          accounts: [ this._address ]
        })

        this._watcher = new ChannelWatcher(60 * 1000, this._api)
        this._watcher.on('channelClose', () => {
          debug('channel closing; triggering auto-disconnect')
          // TODO: should we also close our own channel?
          this._disconnect()
        })

        // TODO: is this an attack vector, if not telling the plugin about their channel
        // causes them to open another channel?

        const channelProtocolData = []
        if (!this._channel) {
          this._channel = await this._createOutgoingChannel()
          // TODO: can we call 'channel' and 'fund_channel' here at the same time?

          channelProtocolData.push({
            protocolName: 'channel',
            contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
            data: Buffer.from(this._channel, 'hex')
          })
        }

        // used to make sure we don't go over the limit
        this._channelDetails = await this._api.getPaymentChannel(this._channel)

        if (!this._clientChannel) {
          debug('no client channel has been established; requesting')
          channelProtocolData.push({
            protocolName: 'fund_channel',
            contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
            data: Buffer.from(this._address)
          })
        }

        if (channelProtocolData.length) {
          const channelResponse = await this._call(null, {
            type: BtpPacket.TYPE_MESSAGE,
            requestId: await util._requestId(),
            data: { protocolData: channelProtocolData }
          })

          if (!this._clientChannel) {
            const fundChannelResponse = channelResponse
              .protocolData
              .filter(p => p.protocolName === 'fund_channel')[0]

            this._clientChannel = fundChannelResponse.data
              .toString('hex')
              .toUpperCase()
          }
        }

        // TODO: should this occur as part of info or should the connector send us a
        // separate message to inform us that they have a channel to us?
        if (this._clientChannel) {
          this._paychan = await this._api.getPaymentChannel(this._clientChannel)

          // don't accept any channel that isn't for us
          if (this._paychan.destination !== this._address) {
            await this._disconnect()
            return reject(new Error('Fatal: Payment channel destination is not ours; Our connector is likely malicious'))
          }

          // don't accept any channel that can be closed too fast
          if (this._paychan.settleDelay < util.MIN_SETTLE_DELAY) {
            await this._disconnect()
            return reject(new Error('Fatal: Payment channel settle delay is too short; Our connector is likely malicious'))
          }

          // don't accept any channel that is closing
          if (this._paychan.expiration) {
            await this._disconnect()
            return reject(new Error('Fatal: Payment channel is already closing; Our connector is likely malicious'))
          }

          // don't accept any channel with a static cancel time
          if (this._paychan.cancelAfter) {
            await this._disconnect()
            return reject(new Error('Fatal: Payment channel has a hard cancel; Our connector is likely malicious'))
          }

          this._bestClaim = {
            amount: util.xrpToDrops(this._paychan.balance)
          }

          // load the best claim from the crash cache
          if (this._store) {
            const bestClaim = JSON.parse(await this._store.get(this._clientChannel))
            if (bestClaim.amount > this._bestClaim) {
              this._bestClaim = bestClaim
              // TODO: should it submit the recovered claim right away or wait?
            }
          }

          debug('loaded best claim of', this._bestClaim)
          this._watcher.watch(this._clientChannel)
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

  async disconnect () {
    if (this._ws) {
      // complete any funding txes before we disconnect
      if (this._funding) {
        await this._funding
      }

      // bind error to no-op so that it doesn't crash before we
      // submit our claim
      this._ws.on('error', e => {
        debug('ws error:', e.message)
      })

      await Promise.race([
        new Promise(resolve => {
          this._ws.close(1000, 'disconnect', resolve)
          this._ws = null
        }),
        new Promise(resolve => setTimeout(resolve, 10))
      ])

      if (this._store) {
        await this._writeQueue
      }

      if (this._bestClaim.amount === '0') return
      if (this._bestClaim.amount === util.xrpToDrops(this._paychan.balance)) return

      debug('creating claim tx')
      const claimTx = await this._api.preparePaymentChannelClaim(this._address, {
        balance: util.dropsToXrp(this._bestClaim.amount),
        channel: this._clientChannel,
        signature: this._bestClaim.signature.toUpperCase(),
        publicKey: this._paychan.publicKey
      })

      debug('signing claim transaction')
      const signedTx = this._api.sign(claimTx.txJSON, this._secret)

      debug('submitting claim transaction ', claimTx)
      const {resultCode, resultMessage} = await this._api.submit(signedTx.signedTransaction)
      if (resultCode !== 'tesSUCCESS') {
        console.error('WARNING: Error submitting claim: ', resultMessage)
        throw new Error('Could not claim funds: ', resultMessage)
      }

      debug('done')
    }
  }

  isConnected () {
    return !!this._ws
  }

  async _handleBtpMessage (from, message) {
    const protocols = message.protocolData
    if (!protocols.length) return

    const channelProtocol = protocols.filter(p => p.protocolName === 'channel')[0]
    if (channelProtocol) {
      debug('got notification of changing channel details')  
      const channel = channelProtocol.data
        .toString('hex')
        .toUpperCase()

      // we just use this call to refresh the channel details
      // TODO: can use this protocol to establish client paychan at a later date
      // than the connection.
      if (channel !== this._clientChannel) return
      this._paychan = await this._api.getPaymentChannel(channel)
    }
  }

  async sendData (buffer) {
    const response = await this._call(null, {
      type: BtpPacket.TYPE_MESSAGE,
      requestId: await util._requestId(),
      data: { protocolData: [{
        protocolName: 'ilp',
        contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
        data: buffer
      }] }
    })

    return response.protocolData
      .filter(p => p.protocolName === 'ilp')
      .data
  }

  async sendMoney (transferAmount) {
    if (!this._lastClaim) {
      const response = await this._call(null, {
        type: BtpPacket.TYPE_MESSAGE,
        requestId: await util._requestId(),
        data: { protocolData: [{
          protocolName: 'last_claim',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: Buffer.from([])
        }] }
      })

      const primary = response.protocolData[0]
      if (primary.protocolName !== 'claim')
      this._lastClaim = JSON.parse(primary.data.toString())
    }

    // TODO: this method of having the latest claim cached will fail on multiple clients
    // connected to one server. It could be switched to fetch the last claim every time,
    // but then the latency would effectively double.

    debug('given last claim of', this._lastClaim)
    const encodedClaim = util.encodeClaim(this._lastClaim.amount, this._channel)

    // If they say we haven't sent them anything yet, it doesn't matter
    // whether they possess a valid claim to say that.
    if (this._lastClaim.amount !== '0') {
      try {
        nacl.sign.detached.verify(
          encodedClaim,
          Buffer.from(this._lastClaim.signature, 'hex'),
          this._keyPair.publicKey
        )
      } catch (err) {
        // TODO: if these get out of sync, all subsequent transfers of money will fail
        debug('invalid claim signature for', this._lastClaim.amount)
        throw new Error('Our last outgoing signature for ' + this._lastClaim.amount + ' is invalid')
      }
    } else {
      debug('signing first claim')
    }

    const amount = new BigNumber(this._lastClaim.amount).add(transferAmount).toString()
    const newClaimEncoded = util.encodeClaim(amount, this._channel)
    const signature = Buffer
      .from(nacl.sign.detached(newClaimEncoded, this._keyPair.secretKey))
      .toString('hex')
      .toUpperCase()

    const aboveThreshold = new BigNumber(util
      .xrpToDrops(this._channelDetails.amount))
      .div(2) // TODO: configurable threshold?
      .lessThan(amount)

    // if the claim we're signing is for more than half the channel's balance, add some funds
    // TODO: should there be a balance check to make sure we have enough to fund the channel?
    // TODO: should this functionality be enabled by default?
    if (!this._funding && aboveThreshold) {
      debug('adding funds to channel')
      this._funding = util.fundChannel({
        api: this._api,
        channel: this._channel,
        address: this._address,
        secret: this._secret,
        // TODO: configurable fund amount?
        amount: util.xrpToDrops(OUTGOING_CHANNEL_DEFAULT_AMOUNT_XRP)
      })
        .then(async () => {
          this._funding = false
          // send a 'channel' call in order to refresh details
          await this._call(null, {
            type: BtpPacket.TYPE_MESSAGE,
            requestId: await util._requestId(),
            data: { protocolData: [{
              protocolName: 'channel',
              contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
              data: Buffer.from(this._channel, 'hex')
            }] }
          })
        })
        .catch((e) => {
          debug('fund tx/notify failed:', e)
          this._funding = false
        })
    }

    return this._call(null, {
      type: BtpPacket.TYPE_TRANSFER,
      requestId: await util._requestId(),
      data: {
        amount: transferAmount,
        protocolData: [{
          protocolName: 'claim',
          contentType: BtpPacket.MIME_APPLICATION_JSON,
          data: Buffer.from(JSON.stringify({ amount, signature }))
        }]
      }
    })
  }

  _handleBtpTransfer (from, btpData) {
    const transferAmount = btpData.amount
    const primary = btpData.protocolData[0]

    if (primary.protocolName === 'claim') {
      const nextAmount = new BigNumber(this._bestClaim.amount).add(transferAmount)
      const { amount, signature } = JSON.parse(primary.data.toString())
      const encodedClaim = util.encodeClaim(amount, this._clientChannel)

      if (nextAmount.greaterThan(amount)) {
        debug('expected claim for', nextAmount.toString(), 'got', amount)
        throw new Error('Got a claim that was too low. Expected ' +
          nextAmount.toString() + ' got ' + amount)
      }

      try {
        nacl.sign.detached.verify(
          encodedClaim,
          Buffer.from(signature, 'hex'),
          Buffer.from(this._paychan.publicKey.substring(2), 'hex')
        )
      } catch (err) {
        debug('invalid claim signature for', amount)
        throw new Error('Invalid claim signature for: ' + amount)
      }

      debug('got new best claim for', amount)
      this._bestClaim = { amount, signature }

      if (this._store) {
        this._writeQueue = this._writeQueue.then(() => {
          return this._store.put(this._clientChannel, JSON.stringify(this._bestClaim))
        })
      }
    }
  }

  async _handleOutgoingBtpPacket (to, btpPacket) {
    try { 
      await new Promise(resolve => this._ws.send(BtpPacket.serialize(btpPacket), resolve))
    } catch (e) {
      debug('unable to send btp message to client: ' + e.message, 'btp packet:', JSON.stringify(btpPacket))
    }
  }
}

module.exports = Plugin
