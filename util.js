const bignum = require('bignum')
const crypto = require('crypto')
const addressCodec = require('ripple-address-codec')

const INFO_REQUEST_ALL = 2
const MIN_SETTLE_DELAY = 3600

const DROPS_PER_XRP = 1000000
const dropsToXrp = (drops) => new BigNumber(drops).div(DROPS_PER_XRP).toString()
const xrpToDrops = (xrp) => new BigNumber(xrp).mul(DROPS_PER_XRP).toString()

function hmac (key, message) {
  const h = crypto.createHmac('sha256', key)
  h.update(message)
  return h.digest()
}

function computeChannelId (src, dest, sequence) {
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
} 

function encodeClaim (amount, id) {
  return Buffer.concat([
    Buffer.from('CLM\0'),
    Buffer.from(id, 'hex'),
    bignum(amount).toBuffer({
      endian: 'big',
      size: 8
    })
  ])
}

function randomTag {
  return bignum.fromBuffer(crypto.randomBytes(4), {
    endian: 'big',
    size: 4
  }).toNumber()
}

async function _requestId () {
  return new Promise((resolve, reject) => {
    crypto.randomBytes(4, (err, buf) => {
      if (err) reject(err)
      resolve(buf.readUInt32BE(0))
    })
  })
}

function checkChannelExpiry (expiry) {
  const isAfter = moment().add(MIN_SETTLE_DELAY, 'seconds').isAfter(expiry)

  if (isAfter) {
    debug('incoming payment channel expires too soon. ' +
        'Minimum expiry is ' + MIN_SETTLE_DELAY + ' seconds.')
    throw new Error('incoming channel expires too soon')
  }
}

module.exports = {
  INFO_REQUEST_ALL,
  MIN_SETTLE_DELAY, 
  DROPS_PER_XRP,
  dropsToXrp,
  xrpToDrops,
  hmac,
  computeChannelId,
  encodeClaim,
  randomTag,
  _requestId,
  checkChannelExpiry
}
