const crypto = require('crypto')
const addressCodec = require('ripple-address-codec')
const nacl = require('tweetnacl')
const { RippleAPI } = require('ripple-lib')
const BtpPacket = require('btp-packet')
const BigNumber = require('bignumber.js')
const WebSocket = require('ws')
const assert = require('assert')
const debug = require('debug')('ilp-plugin-multi-xrp-paychan')
const AbstractBtpPlugin = require('./btp-plugin')
const StoreWrapper = require('./store-wrapper')
const base64url = require('base64url')
const bignum = require('bignum')
const OUTGOING_CHANNEL_DEFAULT_AMOUNT = Math.pow(10, 6) // 1 XRP
const CHANNEL_KEYS = 'ilp-plugin-multi-xrp-paychan-channel-keys'
const util = require('./util')

function tokenToAccount (token) {
  return base64url(crypto.createHash('sha256').update(token).digest('sha256'))
}

function ilpAddressToAccount (prefix, ilpAddress) {
  if (ilpAddress.substr(0, prefix.length) !== prefix) {
    throw new Error('ILP address (' + ilpAddress + ') must start with prefix (' + prefix + ')')
  }

  return ilpAddress.substr(prefix.length).split('.')[0]
}

class Plugin extends AbstractBtpPlugin {
  constructor (opts) {
    super()
    this._prefix = opts.prefix
    this._port = opts.port || 3000
    this._wsOpts = opts.wsOpts || { port: this._port }
    this._currencyScale = 6
    this._modeInfiniteBalances = !!opts.debugInfiniteBalances

    this._xrpServer = opts.xrpServer
    this._secret = opts.secret
    this._address = opts.address
    this._api = new RippleAPI({ server: this._xrpServer })
    this._bandwidth = opts.bandwidth || 1000

    this._log = opts._log || console
    this._wss = null
    this._balances = new StoreWrapper(opts._store)
    this._ephemeral = new Map()
    this._paychans = new Map()
    this._clientPaychans = new Map()
    this._connections = new Map()
    this._funding = new Map()

    this.on('incoming_fulfill', this._handleIncomingFulfill.bind(this))
    this.on('incoming_reject', this._handleIncomingReject.bind(this))

    if (this._modeInfiniteBalances) {
      this._log.warn('(!!!) granting all users infinite balances')
    }
  }

  _validatePaychanDetails (paychan) {
    const settleDelay = paychan.settleDelay
    if (settleDelay < util.MIN_SETTLE_DELAY) {
      debug(`incoming payment channel has a too low settle delay of ${settleDelay.toString()}` +
        ` seconds. Minimum settle delay is ${util.MIN_SETTLE_DELAY} seconds.`)
      throw new Error('settle delay of incoming payment channel too low')
    }

    if (paychan.cancelAfter) {
      util.checkChannelExpiry(paychan.cancelAfter)
    }

    if (paychan.expiration) {
      util.checkChannelExpiry(paychan.expiration)
    }

    if (paychan.destination !== this._address) {
      debug('incoming channel destination is not our address: ' +
        paychan.destination)
      throw new Error('Channel destination address wrong')
    }
  }

  _extraInfo (from) {
    const account = ilpAddressToAccount(this._prefix, from)
    const channel = this._balances.get(account + ':channel')
    const clientChannel = this._balances.get(account + ':client_channel')
    const address = this._address
    
    return {
      channel,
      clientChannel,
      address,
      account: from
    }
  }

  async connect () {
    if (this._wss) return

    await this._api.connect()
    await this._api.connection.request({
      command: 'subscribe',
      accounts: [ this._address ]
    })

    debug('listening on port ' + this._port)
    const wss = this._wss = new WebSocket.Server(this._wsOpts)
    wss.on('connection', (wsIncoming) => {
      debug('got connection')
      let token
      let channel
      let account

      // The first message must be an auth packet
      // with the macaroon as the auth_token
      let authPacket
      wsIncoming.once('message', async (binaryAuthMessage) => {
        try {
          authPacket = BtpPacket.deserialize(binaryAuthMessage)
          assert.equal(authPacket.type, BtpPacket.TYPE_MESSAGE, 'First message sent over BTP connection must be auth packet')
          assert(authPacket.data.protocolData.length >= 2, 'Auth packet must have auth and auth_token subprotocols')
          assert.equal(authPacket.data.protocolData[0].protocolName, 'auth', 'First subprotocol must be auth')
          for (let subProtocol of authPacket.data.protocolData) {
            if (subProtocol.protocolName === 'auth_token') {
              // TODO: Do some validation on the token
              token = subProtocol.data
              account = tokenToAccount(token)

              let connections = this._connections.get(account)
              if (!connections) {
                this._connections.set(account, connections = new Set())
              }

              connections.add(wsIncoming)
            }
          }

          assert(token, 'auth_token subprotocol is required')

          const channelKey = account + ':channel'
          await this._balances.load(channelKey)
          const existingChannel = this._balances.get(channelKey)

          await this._balances.load(account)
          await this._balances.load(account + ':claim')
          await this._balances.load(account + ':client_channel')
          await this._balances.load(account + ':outgoing_balance')
          const existingClientChannel = this._balances.get(account + ':client_channel')

          if (existingChannel) {
            // TODO: DoS vector by requesting paychan on user connect?
            const paychan = await this._api.getPaymentChannel(existingChannel)
            this._validatePaychanDetails(paychan)
            this._paychans.set(account, paychan)
          }

          if (existingClientChannel) {
            const paychan = await this._api.getPaymentChannel(existingClientChannel)
            this._clientPaychans.set(account, paychan)
          }

          this._ephemeral.set(account, this._balances.get(account))
          wsIncoming.send(BtpPacket.serializeResponse(authPacket.requestId, []))
        } catch (err) {
          if (authPacket) {
            const errorResponse = BtpPacket.serializeError({
              code: 'F00',
              name: 'NotAcceptedError',
              data: err.message,
              triggeredAt: new Date().toISOString()
            }, authPacket.requestId, [])
            wsIncoming.send(errorResponse)
          }
          wsIncoming.close()

          // clean up paychan info when all connections close
          // TODO: way to clean up ephemeral balance or balance cache?
          if (this._connections.get(account).size === 0) {
            this._paychans.delete(account)
          }

          return
        }

        debug('connection authenticated')

        wsIncoming.on('message', (binaryMessage) => {
          let btpPacket
          try {
            btpPacket = BtpPacket.deserialize(binaryMessage)
          } catch (err) {
            wsIncoming.close()
          }
          debug(`account ${account}: processing btp packet ${JSON.stringify(btpPacket)}`)
          try {
            let operation = Promise.resolve()
            if (btpPacket.type === BtpPacket.TYPE_PREPARE) {
              operation = this._handleIncomingBtpPrepare(account, btpPacket)
            }
            debug('packet is authorized, forwarding to host')
            operation.then(() => {
              this._handleIncomingBtpPacket(this._prefix + account, btpPacket)
            })
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
    })

    return null
  }

  async disconnect () {
    if (this._wss) {
      return new Promise(resolve => {
        this._wss.close(resolve)
        this._wss = null
      })
    }
  }

  isConnected () {
    return !!this._wss
  }

  async _fundOutgoingChannel (account, primary) {
    await this._balances.load(account + ':client_channel')
    await this._balances.load(account + ':outgoing_balance')

    const existing = this._balances.get(account + ':client_channel')
    if (existing) {
      const paychan = await this._api.getPaymentChannel(existing)
      this._clientChannels.set(account, paychan)
      return existing
    }

    this._balances.setCache(account + ':client_channel', true)

    const outgoingAccount = primary.data.toString() 
    // TODO: validate the account

    const keyPairSeed = util.hmac(this._secret, CHANNEL_KEYS + account)
    const keyPair = nacl.sign.keyPair.fromSeed(keyPairSeed)
    const txTag = util.randomTag()
    const tx = await this._api.preparePaymentChannelCreate(this._address, {
      amount: dropsToXrp(OUTGOING_CHANNEL_DEFAULT_AMOUNT),
      destination: outgoingAccount,
      settleDelay: util.MIN_SETTLE_DELAY,
      publicKey: 'ED' + Buffer.from(keyPair.publicKey).toString('hex').toUpperCase(),
      sourceTag: txTag
    })

    const signedTx = this._api.sign(tx.txJSON, this._secret)
    const result = await this._api.submit(signedTx.signedTransaction)

    if (result.resultCode !== 'tesSUCCESS') {
      const message = 'Error creating the payment channel: ' + result.resultCode + ' ' + result.resultMessage
      debug(message)
      return
    }

    return new Promise((resolve) => {
      const handleTransaction = async (ev) => {
        if (ev.transaction.SourceTag !== txTag) return
        if (ev.transaction.Account !== this._address) return

        const clientChannelId = util.computeChannelId(
          ev.transaction.Account,
          ev.transaction.Destination,
          ev.transaction.Sequence)

        this._balances.set(account + ':outgoing_balance', '0')
        this._balances.set(account + ':client_channel', clientChannelId)

        const paychan = await this._api.getPaymentChannel(clientChannelId)
        this._clientPaychans.set(account, paychan)

        setImmediate(() => this._api.connection
          .removeListener('transaction', handleTransaction))
        resolve(clientChannelId)
      }

      this._api.connection.on('transaction', handleTransaction)
    })
  }

  async _handleBtpMessage (from, message) {
    const account = ilpAddressToAccount(this._prefix, from)
    const protocols = message.protocolData
    if (!protocols.length) return

    const fundChannel = protocols.filter(p => p.protocolName === 'fund_channel')[0]
    const channelProtocol = protocols.filter(p => p.protocolName === 'channel')[0]

    if (channelProtocol) {
      debug('got message for incoming channel on account', account)
      const channel = channelProtocol.data
        .toString('hex')
        .toUpperCase()

      const channelKey = account + ':channel'
      const existingChannel = this._balances.get(channelKey)

      if (existingChannel && existingChannel !== channel) {
        throw new Error(`there is already an existing channel on this account
          and it doesn't match the 'channel' protocolData`)
      }

      // Because this reloads channel details even if the channel exists,
      // we can use it to refresh the channel details after extra funds are
      // added
      const paychan = await this._api.getPaymentChannel(channel)
      this._validatePaychanDetails(paychan)
      this._paychans.set(account, paychan)
      this._balances.set(account + ':channel', channel)
      debug('registered payment channel for', account)
    }

    if (fundChannel) {
      const incomingChannel = this._paychans.get(account)

      if (new BigNumber(util.xrpToDrops(incomingChannel.amount)).lessThan(MIN_INCOMING_CHANNEL)) {
        debug('denied outgoing paychan request; not enough has been escrowed')
        throw new Error('not enough has been escrowed in channel; must put ' +
          MIN_INCOMING_CHANNEL + ' drops on hold')
      }

      debug('an outgoing paychan has been authorized for', account, '; establishing')
      const clientChannelId = await this._fundOutgoingChannel(account, fundChannel)

      // TODO: should the channel subprotocol be merged with fund_channel, such that the
      // connector will see that enough funds have been escrowed to them and then they can
      // open a counter-channel?

      return [{
        protocolName: 'fund_channel',
        contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
        data: Buffer.from(clientChannelId, 'hex')
      }]
    }
    return []
  }

  _handleOutgoingPrepare (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.to)
    const clientChannel = this._balances.get(account + ':client_channel')

    if (!clientChannel) {
      throw new Error('No client channel established for account ' + account)
    }
  }

  async _handleIncomingBtpPrepare (account, btpPacket) {
    const paychan = this._paychans.get(account)
    if (!paychan) {
      throw new Error(`Incoming traffic won't be accepted until a channel to
        the connector is established`)
    }

    const prepare = btpPacket.data
    const primary = prepare.protocolData[0]
    if (!primary || primary.protocolName !== 'ilp') {
      throw new Error('ILP packet is required')
    }
    // const ilp = IlpPacket.deserializeIlpPayment(prepare.protocolData[0].data)

    const prepared = new BigNumber(this._ephemeral.get(account) || 0)
    const lastClaim = this._getLastClaim(account)
    const lastValue = new BigNumber(lastClaim.amount)

    const newPrepared = prepared.add(prepare.amount)
    const unsecured = newPrepared.sub(lastValue)
    debug(unsecured.toString(), 'unsecured; last claim is', lastValue.toString(), 'prepared amount', prepare.amount, 'newPrepared', newPrepared.toString(), 'prepared', prepared.toString())

    if (unsecured.greaterThan(this._bandwidth)) {
      throw new Error('Insufficient bandwidth, used: ' + unsecured + ' max: ' + this._bandwidth)
    }

    if (newPrepared.greaterThan(util.xrpToDrops(paychan.amount))) {
      throw new Error('Insufficient funds, have: ' + newPrepared + ' need: ' + prepare.amount)
    }

    this._ephemeral.set(account, newPrepared.toString())

    debug(`account ${account} debited ${prepare.amount} units, new balance ${newPrepared}`)
  }

  _handleOutgoingFulfill (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.to)
    const balanceKey = account + ':outgoing_balance'

    const currentBalance = new BigNumber(this._balances.get(balanceKey) || 0)
    const newBalance = currentBalance.add(transfer.amount)

    // TODO: fund if above a certain threshold (50%?)

    this._balances.set(balanceKey, newBalance.toString())
    debug(`account ${balanceKey} added ${transfer.amount} units, new balance ${newBalance}`)

    // sign a claim
    const channel = this._balances.get(account + ':client_channel')
    const encodedClaim = util.encodeClaim(newBalance.toString(), channel)
    const keyPairSeed = util.hmac(this._secret, CHANNEL_KEYS + account)
    const keyPair = nacl.sign.keyPair.fromSeed(keyPairSeed)
    const signature = nacl.sign.detached(encodedClaim, keyPair.secretKey)

    debug(`signing outgoing claim for ${newBalance.toString()} drops on ` +
      `channel ${channel}`)

    const aboveThreshold = new BigNumber(util
      .xrpToDrops(this._clientPaychans.get(account).amount))
      .div(2) // TODO: configurable threshold?
      .lessThan(newBalance.toString())

    // if the claim we're signing is for more than half the channel's balance, add some funds
    // TODO: can there be multiple funding transactions in flight?
    // TODO: should the amount of funding ramp up or go linearly?
    if (!this._funding.get(account) && aboveThreshold) {
      this._funding.set(account, true)
      util.fundChannel({
        api: this._api,
        channel: this._channel,
        // TODO: configurable fund amount?
        amount: xrpToDrops(OUTGOING_CHANNEL_DEFAULT_AMOUNT)
      })
        .then(async () => {
          this._funding.set(account, false)
          await this._call(transfer.to, {
            type: BtpPacket.TYPE_MESSAGE,
            requestId: await util._requestId(),
            data: { protocolData: [{
              protocolName: 'channel',
              contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
              data: Buffer.from(channel, 'hex')
            }] }
          })
        })
        .catch(() => {
          this._funding.set(account, false)
        })
    }

    return [{
      protocolName: 'claim',
      contentType: 2,
      data: Buffer.from(JSON.stringify({
        amount: newBalance.toString(),
        signature: Buffer.from(signature).toString('hex')
      }))
    }]
  }

  async _handleIncomingFulfill (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.from)
    const balance = new BigNumber(this._balances.get(account) || 0)
    const newBalance = balance.add(transfer.amount)

    this._balances.set(account, newBalance.toString())

    debug(`account ${account} finalized ${transfer.amount} units, new balance ${newBalance}`)
  }

  _getFulfillConditionProtocolData (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.from)
    const claim = this._balances.get(account + ':claim') || JSON.stringify({
      amount: '0'
    })

    return [{
      protocolName: 'claim',
      contentType: BtpPacket.MIME_APPLICATION_JSON,
      data: Buffer.from(claim)
    }]
  }

  _handleClaim (account, claim) {
    let valid = false
    const channel = this._balances.get(account + ':channel')
    const paychan = this._paychans.get(account)
    const { amount, signature } = claim
    const encodedClaim = util.encodeClaim(amount, channel)

    try {
      valid = nacl.sign.detached.verify(
        encodedClaim,
        Buffer.from(signature, 'hex'),
        Buffer.from(paychan.publicKey.substring(2), 'hex')
      )
    } catch (err) {
      debug('verifying signature failed:', err.message)
    }
    // TODO: better reconciliation if claims are invalid
    if (!valid) {
      debug(`got invalid claim signature ${signature} for amount ${amount} drops`)
      /*throw new Error('got invalid claim signature ' +
        signature + ' for amount ' + amount + ' drops')*/
      throw new Error('Invalid claim: invalid signature')
    }

    // validate claim against balance
    const channelBalance = util.xrpToDrops(paychan.amount)
    if (new BigNumber(amount).gt(channelBalance)) {
      const message = 'got claim for amount higher than channel balance. amount: ' + amount + ', incoming channel balance: ' + channelBalance
      debug(message)
      //throw new Error(message)
      throw new Error('Invalid claim: claim amount (' + amount + ') exceeds channel balance (' + channelBalance + ')')
    }

    const lastClaim = this._getLastClaim(account)
    const lastValue = new BigNumber(lastClaim.amount)
    if (lastValue.lt(amount)) {
      this._balances.set(account + ':claim', JSON.stringify(claim))
    }
    debug('set new claim for amount', amount)
  }

  // TODO: handle incoming fulfill response
  _handleIncomingFulfillResponse (transfer, response) {
    const account = ilpAddressToAccount(this._prefix, transfer.from)

    console.log('response:', response)
    const [ jsonClaim ] = response.protocolData
      .filter(p => p.protocolName === 'claim')
    const claim = JSON.parse(jsonClaim.data.toString())
    console.log('claim:', claim)

    if (!claim) {
      debug('no claim was returned with transfer id=' + transfer.id)
      return
    }

    try {
      this._handleClaim(account, claim)
    } catch (e) {
      debug(e.message)
    }
  }

  _getLastClaim (account) {
    return JSON.parse(this._balances.get(account + ':claim') || '{"amount":"0"}')
  }

  async _handleIncomingReject (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.from)
    const prepared = new BigNumber(this._ephemeral.get(account) || 0)
    const newPrepared = prepared.sub(transfer.amount)

    this._ephemeral.set(account, newPrepared.toString())

    debug(`account ${account} credited ${transfer.amount} units, new balance ${newPrepared}`)
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
    if (to.substring(0, this._prefix.length) !== this._prefix) {
      throw new Error('Invalid destination "' + to + '", must start with prefix: ' + this._prefix)
    }

    const account = ilpAddressToAccount(this._prefix, to)

    const connections = this._connections.get(account)

    if (!connections) {
      throw new Error('No clients connected for account ' + account)
    }

    const results = Array.from(connections).map(wsIncoming => {
      const result = new Promise(resolve => wsIncoming.send(BtpPacket.serialize(btpPacket), resolve))

      result.catch(err => {
        const errorInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err)
        debug('unable to send btp message to client: ' + errorInfo, 'btp packet:', JSON.stringify(btpPacket))
      })
    })

    await Promise.all(results)

    return null
  }
}

module.exports = Plugin
