const crypto = require('crypto')
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
const MIN_SETTLE_DELAY = 3600
const bignum = require('bignum')

const COST_OF_PAYCHAN = '5000000'
const CHANNEL_KEYS = 'ilp-plugin-multi-xrp-paychan-channel-keys'
const OUTGOING_CHANNEL_DEFAULT_AMOUNT = Math.pow(10, 6) // 1 XRP
const EMPTY_CONDITION = base64url(crypto.createHash('sha256').update(Buffer.alloc(32)).digest())
const DROPS_PER_XRP = 1000000
const dropsToXrp = (drops) => new BigNumber(drops).div(DROPS_PER_XRP).toString()
const xrpToDrops = (xrp) => new BigNumber(xrp).mul(DROPS_PER_XRP).toString()
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

function tokenToAccount (token) {
  return base64url(crypto.createHash('sha256').update(token).digest('sha256'))
}

function ilpAddressToAccount (prefix, ilpAddress) {
  if (ilpAddress.substr(0, prefix.length) !== prefix) {
    throw new Error('ILP address (' + ilpAddress + ') must start with prefix (' + prefix + ')')
  }

  return ilpAddress.substr(prefix.length).split('.')[0]
}

function checkChannelExpiry (expiry) {
  const isAfter = moment().add(MIN_SETTLE_DELAY, 'seconds').isAfter(expiry)

  if (isAfter) {
    debug('incoming payment channel expires too soon. ' +
        'Minimum expiry is ' + MIN_SETTLE_DELAY + ' seconds.')
    throw new Error('incoming channel expires too soon')
  }
}

class Plugin extends AbstractBtpPlugin {
  constructor (opts) {
    super()
    this._prefix = opts.prefix
    this._port = opts.port || 3000
    this._wsOpts = opts.wsOpts || { port: this._port }
    this._currencyScale = 6
    this._modeInfiniteBalances = !!opts.debugInfiniteBalances

    this._server = opts.server
    this._secret = opts.secret
    this._address = opts.address
    this._api = new RippleAPI({ server: this._server })
    this._bandwidth = opts.bandwidth || 1000

    this._log = opts._log || console
    this._wss = null
    this._balances = new StoreWrapper(opts._store)
    this._ephemeral = new Map()
    this._paychans = new Map()
    this._connections = new Map()

    this.on('incoming_fulfill', this._handleIncomingFulfill.bind(this))
    this.on('incoming_reject', this._handleIncomingReject.bind(this))

    if (this._modeInfiniteBalances) {
      this._log.warn('(!!!) granting all users infinite balances')
    }
  }

  async connect () {
    if (this._wss) return

    await this._api.connect()

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
            } else if (subProtocol.protocolName === 'channel') {
              channel = subProtocol.data.toString('hex').toUpperCase()
            }
          }

          assert(token, 'auth_token subprotocol is required')
          assert(channel, 'channel subprotocol is required')

          const channelKey = account + ':channel'
          await this._balances.load(channelKey)
          const existingChannel = this._balances.get(channelKey)

          if (existingChannel && existingChannel !== channel) {
            throw new Error(`existing channel ${existingChannel} does not match subprotocol channel ${channel}`)
          } else {
            this._balances.set(channelKey, channel)
          }

          // TODO: DoS vector by requesting paychan on user connect?
          const paychan = await this._api.getPaymentChannel(channel)
          await this._balances.load(account)
          await this._balances.load(account + ':claim')

          const settleDelay = paychan.settleDelay
          if (settleDelay < MIN_SETTLE_DELAY) {
            debug(`incoming payment channel has a too low settle delay of ${settleDelay.toString()}` +
              ` seconds. Minimum settle delay is ${MIN_SETTLE_DELAY} seconds.`)
            throw new Error('settle delay of incoming payment channel too low')
          }

          if (paychan.cancelAfter) {
            checkChannelExpiry(paychan.cancelAfter)
          }

          if (paychan.expiration) {
            checkChannelExpiry(paychan.expiration)
          }

          if (paychan.destination !== this._address) {
            debug('incoming channel destination is not our address: ' +
              paychan.destination)
            throw new Error('Channel destination address wrong')
          }

          this._ephemeral.set(account, this._balances.get(account))
          this._paychans.set(account, paychan)

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

  disconnect () {
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
      return 
    }

    this._balances.setCache(account + ':client_channel', true)

    const outgoingAccount = primary.data.toString() 
    // TODO: validate the account

    const keyPairSeed = hmac(this._secret, CHANNEL_KEYS + account)
    const keyPair = nacl.sign.keyPair.fromSeed(keyPairSeed)
    const txTag = randomTag()
    const tx = await this._api.preparePaymentChannelCreate(this._address, {
      amount: dropsToXrp(OUTGOING_CHANNEL_DEFAULT_AMOUNT),
      destination: outgoingAccount,
      settleDelay: MIN_SETTLE_DELAY,
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

    await new Promise((resolve) => {
      const handleTransaction = (ev) => {
        if (ev.transaction.SourceTag !== txTag) return
        if (ev.transaction.Account !== this._address) return

        this._balances.set(account + ':outgoing_balance', '0')
        this._balances.set(account + ':client_channel', computeChannelId(
          ev.transaction.Account,
          ev.transaction.Destination,
          ev.transaction.Sequence))

        setImmediate(() => this._api.connection
          .removeListener('transaction', handleTransaction))
        resolve()
      }

      this._api.connection.on('transaction', handleTransaction)
    })
  }

  async _handleBtpMessage (account, btpPacket) {
    const message = btpPacket.data
    const primary = message.protocolData[0]

    if (primary && primary.protocolName === 'fund_channel') {
      if (message.amount !== COST_OF_PAYCHAN) {
        throw new Error('Fund channel transfer must give 5 XRP to cover reserve')
      }

      if (message.executionCondition !== EMPTY_CONDITION) {
        throw new Error('Fund channel transfer must have SHA256(0 * 32) as condition')
      }

      const secondary = message.protocolData[1]
      if (secondary.protocolName !== 'fund_channel_claim') {
        throw new Error('Fund channel transfer must come with an up front claim')
      }

      const lastClaim = this._getLastClaim(account)
      const lastValue = new BigNumber(lastClaim.amount)

      this._handleClaim(account, {
        amount: lastValue.add(COST_OF_PAYCHAN),
        signature: secondary.data.toString('hex').toUpperCase()
      })

      const balance = new BigNumber(this._balances.get(account) || 0)
      const newBalance = balance.add(COST_OF_PAYCHAN)

      const prepared = new BigNumber(this._ephemeral.get(account) || 0)
      const newPrepared = prepared.add(COST_OF_PAYCHAN)

      this._ephemeral.set(account, newPrepared.toString())
      this._balances.set(account, newBalance.toString())

      debug('an outgoing paychan has been bought for', account, '; establishing')
      setImmediate(() => this._fundOutgoingChannel(account, primary))

      // TODO: should there be any revert to refund the cost if the establishment of a channel
      // somehow fails?
    }
  }

  async _handleIncomingBtpPrepare (account, btpPacket) {
    const prepare = btpPacket.data
    const primary = prepare.protocolData[0]
    if (!primary || primary.protocolName !== 'ilp') {
      throw new Error('ILP packet is required')
    }
    // const ilp = IlpPacket.deserializeIlpPayment(prepare.protocolData[0].data)

    const prepared = new BigNumber(this._ephemeral.get(account) || 0)
    const lastClaim = this._getLastClaim(account)
    const lastValue = new BigNumber(lastClaim.amount)
    const paychan = this._paychans.get(account)

    const newPrepared = prepared.add(prepare.amount)
    const unsecured = newPrepared.sub(lastValue)
    debug(unsecured.toString(), 'unsecured; last claim is', lastValue.toString(), 'prepared amount', prepare.amount, 'newPrepared', newPrepared.toString(), 'prepared', prepared.toString())

    if (unsecured.greaterThan(this._bandwidth)) {
      throw new Error('Insufficient bandwidth, used: ' + unsecured + ' max: ' + this._bandwidth)
    }

    if (newPrepared.greaterThan(xrpToDrops(paychan.amount))) {
      throw new Error('Insufficient funds, have: ' + newPrepared + ' need: ' + prepare.amount)
    }

    this._ephemeral.set(account, newPrepared.toString())

    debug(`account ${account} debited ${prepare.amount} units, new balance ${newPrepared}`)
  }

  async _handleOutgoingFulfill (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.to)
    const balanceKey = account + ':outgoing_balance'
    await this._balances.load(balanceKey)

    const currentBalance = new BigNumber(this._balances.get(balanceKey) || 0)
    const newBalance = currentBalance.add(transfer.amount)

    // TODO: fund if above a certain threshold (50%?)
    // TODO: issue claim

    this._balances.set(balanceKey, newBalance.toString())
    debug(`account ${balanceKey} added ${transfer.amount} units, new balance ${newBalance}`)


    // sign a claim
    const channel = this._balances.get(account + ':client_channel')
    const encodedClaim = encodeClaim(newBalance.toString(), channel)
    const keyPairSeed = hmac(this._secret, CHANNEL_KEYS + account)
    const keyPair = nacl.sign.keyPair.fromSeed(keyPairSeed)
    const signature = nacl.sign.detached(encodedClaim, keyPair.secretKey)

    debug(`signing outgoing claim for ${newBalance.toString()} drops on ` +
      `channel ${channel}`)

    // TODO: issue a fund tx if fundPercent is reached and tell peer about fund tx

    return [{
      protocolName: 'claim',
      contentType: 2,
      data: Buffer.from(JSON.stringify({
        amount: newBalance.toString(),
        signature: Buffer.from(signature).toString('hex')
      })
    }]
  }

  async _handleIncomingFulfill (transfer) {
    const account = ilpAddressToAccount(this._prefix, transfer.from)
    const balance = new BigNumber(this._balances.get(account) || 0)
    const newBalance = balance.add(transfer.amount)

    this._balances.set(account, newBalance.toString())

    debug(`account ${account} finalized ${transfer.amount} units, new balance ${newBalance}`)
  }

  _handleClaim (account, claim) {
    let valid = false
    const channel = this._balances.get(account + ':channel')
    const paychan = this._paychans.get(account)
    const { amount, signature } = claim
    const encodedClaim = encodeClaim(amount, channel)

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
    const channelBalance = xrpToDrops(paychan.amount)
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
