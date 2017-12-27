'use strict'

const crypto = require('crypto')
const EventEmitter = require('events').EventEmitter
const BtpPacket = require('btp-packet')
const IlpPacket = require('ilp-packet')
const base64url = require('base64url')

const { protocolDataToIlpAndCustom, ilpAndCustomToProtocolData } =
  require('./protocol-data-converter')


const int64 = require('./long')

const DEFAULT_TIMEOUT = 5000
const namesToCodes = {
  'UnreachableError': 'T00',
  'NotAcceptedError': 'F00',
  'InvalidFieldsError': 'F01',
  'TransferNotFoundError': 'F02',
  'InvalidFulfillmentError': 'F03',
  'DuplicateIdError': 'F04',
  'AlreadyRolledBackError': 'F05',
  'AlreadyFulfilledError': 'F06',
  'InsufficientBalanceError': 'F07'
}

function jsErrorToBtpError (e) {
  const name = e.name || 'NotAcceptedError'
  const code = namesToCodes[name] || 'F00'

  return {
    code,
    name,
    triggeredAt: new Date(),
    data: JSON.stringify({ message: e.message })
  }
}

const INFO_REQUEST_ACCOUNT = 0 // eslint-disable-line no-unused-vars
const INFO_REQUEST_FULL = 2

/**
 * Abstract base class for building BTP-based ledger plugins.
 *
 * This class takes care of most of the work translating between BTP and the
 * ledger plugin interface (LPI).
 *
 * You need to implement:
 *
 * connect()
 * disconnect()
 * isConnected()
 * getInfo()
 * getAccount()
 * getBalance()
 *
 * This class takes care of:
 *
 * getFulfillment()
 * sendTransfer()
 * sendRequest()
 * fulfillCondition()
 * rejectIncomingTransfer()
 * registerRequestHandler()
 * deregisterRequestHandler()
 *
 * Instead, you need to implement _handleOutgoingBtpPacket(to, btpPacket) which
 * returns a Promise. `to` is the ILP address of the destination peer and
 * `btpPacket` is the BTP packet as a JavaScript object.
 *
 * You can call _handleIncomingBtpPacket(from, btpPacket) to trigger all the
 * necessary LPI events in response to an incoming BTP packet. `from` is the ILP
 * address of the peer and `btpPacket` is the parsed BTP packet.
 */
class AbstractBtpPlugin extends EventEmitter {
  constructor (debug) {
    super()

    this._debug = debug
    this._dataHandler = null
    this._moneyHandler = null
  }

  // don't throw errors even if the event handler throws
  // this is especially important in plugins because
  // errors can prevent the balance from being updated correctly
  _safeEmit () {
    try {
      this.emit.apply(this, arguments)
    } catch (err) {
      const errInfo = (typeof err === 'object' && err.stack) ? err.stack : String(err)
      this._debug('error in handler for event', arguments, errInfo)
    }
  }

  getInfo () {
    return {}
  }

  async _call (to, btpPacket) {
    const requestId = btpPacket.requestId

    this._debug('sending ', btpPacket)

    let callback
    const response = new Promise((resolve, reject) => {
      callback = (type, data) => {
        switch (type) {
          case BtpPacket.TYPE_RESPONSE:
            resolve(data)
            break

          case BtpPacket.TYPE_ERROR:
            reject(new Error(JSON.stringify(data)))
            break

          default:
            throw new Error('Unkown BTP packet type', data)
        }
      }
      this.once('__callback_' + requestId, callback)
    })

    await this._handleOutgoingBtpPacket(to, btpPacket)

    const timeout = new Promise((resolve, reject) =>
      setTimeout(() => {
        this.removeListener('__callback_' + requestId, callback)
        reject(new Error(requestId + ' timed out'))
      }, DEFAULT_TIMEOUT))

    return Promise.race([
      response,
      timeout
    ])
  }

  async _handleIncomingBtpPacket (from, btpPacket) {
    const {type, requestId, data} = btpPacket
    const typeString = BtpPacket.typeToString(type)

    this._debug(`received BTP packet (${typeString}, RequestId: ${requestId}): ${JSON.stringify(data)}`)

    try {
      let result
      switch (type) {
        case BtpPacket.TYPE_RESPONSE:
        case BtpPacket.TYPE_ERROR:
          this.emit('__callback_' + requestId, type, data)
          return
        case BtpPacket.TYPE_PREPARE:
        case BtpPacket.TYPE_FULFILL:
        case BtpPacket.TYPE_REJECT:
          throw new Error('Unsupported BTP packet') 

        case BtpPacket.TYPE_TRANSFER:
          result = await this._handleMoney(from, btpPacket)
          break

        case BtpPacket.TYPE_MESSAGE:
          result = await this._handleData(from, btpPacket)
          break
      }

      this._debug(`replying to request ${requestId} with ${JSON.stringify(result)}`)
      await this._handleOutgoingBtpPacket(from, {
        type: BtpPacket.TYPE_RESPONSE,
        requestId,
        data: { protocolData: result || [] }
      })
    } catch (e) {
      this._debug(`Error processing BTP packet of type ${typeString}: `, e)
      const error = jsErrorToBtpError(e)

      const { code, name, triggeredAt, data } = error

      await this._handleOutgoingBtpPacket(from, {
        type: BtpPacket.TYPE_ERROR,
        requestId,
        data: {
          code,
          name,
          triggeredAt,
          data,
          protocolData: []
        }
      })
      throw e
    }
  }

  async _handleData (from, {requestId, data}) {
    const { ilp, protocolMap } = protocolDataToIlpAndCustom(data)

    // if there are side protocols only
    if (!ilp) {
      if (protocolMap.info) {
        if (Buffer.isBuffer(protocolMap.info) &&
            protocolMap.info.readInt8() === INFO_REQUEST_FULL) {
          // We need to trick each client into thinking that they are on their
          // own separate subledger to force them to use a connector.
          //
          // Otherwise, they will try to deliver locally to each other which
          // may not work since we are actually routing all payments through
          // the parent connector.
          //
          // This wouldn't be necessary if we got rid of the distinction
          // between forwarding and delivery.
          const info = Object.assign({}, this.getInfo())
          info.prefix = from + '.'
          info.connectors = [ from + '.server' ]

          if (this._extraInfo) {
            Object.assign(info, this._extraInfo(from, data))
          }

          return [{
            protocolName: 'info',
            contentType: BtpPacket.MIME_APPLICATION_JSON,
            data: Buffer.from(JSON.stringify(info))
          }]
        } else {
          return [{
            protocolName: 'info',
            contentType: BtpPacket.MIME_TEXT_PLAIN_UTF8,
            data: Buffer.from(this.getAccount())
          }]
        }
      } else if (protocolMap.balance) {
        return [{
          protocolName: 'balance',
          contentType: BtpPacket.MIME_APPLICATION_OCTET_STREAM,
          data: int64.toBuffer(await this._handleGetBalance())
        }]
      } else if (protocolMap.limit) {
        return [{
          protocolName: 'limit',
          contentType: BtpPacket.MIME_APPLICATION_JSON,
          data: Buffer.from(JSON.stringify(await this._handleGetLimit()))
        }]
      } else if (protocolMap.custom) {
        // Don't throw -- this message will be emitted.
      }
    }

    if (this._handleBtpMessage) {
      return this._handleBtpMessage(from, data)
    }

    if (!this._dataHandler) {
      throw new NotAcceptedError('no request handler registered')
    }

    const response = await this._dataHandler(ilp)
    return ilpAndCustomToProtocolData({ ilp: response })
  }

  async _handleMoney (from, {requestId, data}) {
    if (!this._moneyHandler) {
      throw new Error('no money handler registered')
    }

    response = []
    if (!this._handleBtpTransfer) {
      return this._handleBtpTransfer(from, data) || []
    }

    const response = await this._moneyHandler(ilp)
    return ilpAndCustomToProtocolData({ ilp: response })
  }

  registerDataHandler (handler) {
    if (this._dataHandler) {
      throw new Error('requestHandler is already registered')
    }

    if (typeof handler !== 'function') {
      throw new Error('requestHandler must be a function')
    }

    this._debug('registering data handler')
    this._dataHandler = handler
  }

  deregisterDataHandler () {
    this._dataHandler = null
  }

  registerMoneyHandler (handler) {
    if (this._moneyHandler) {
      throw new Error('requestHandler is already registered')
    }

    if (typeof handler !== 'function') {
      throw new Error('requestHandler must be a function')
    }

    this._debug('registering money handler')
    this._moneyHandler = handler
  }

  deregisterMoneyHandler () {
    this._moneyHandler = null
  }
}

async function _requestId () {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(4, (err, buf) => {
      if (err) reject(err)
      resolve(buf.readUInt32BE(0))
    })
  })
}

module.exports = AbstractBtpPlugin
