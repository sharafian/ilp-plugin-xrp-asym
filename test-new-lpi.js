'use strict'

const ILP = require('ilp')
const IlpPluginXrpStateless = require('./index.js')
const IlpPacket = require('ilp-packet')
const base64url = require('base64url')
const crypto = require('crypto')
const IlpPluginXrpServer = require('./server.js')
const Store = require('./redisStore.js')

process.on('unhandledRejection', (e) => {
  console.log('UNHANDLED REJECTION', e)
})

const serverPlugin = new IlpPluginXrpServer({
  prefix: 'test.example.',
  port: 3033,
  address: 'r9Ggkrw4VCfRzSqgrkJTeyfZvBvaG9z3hg',
  secret: 'snRHsS3wLzbfeDNSVmtLKjE6sPMws',
  xrpServer: 'wss://s.altnet.rippletest.net:51233',
  bandwidth: 1000000,
  _store: new Store(null, 'test.example.')
})

const clientPlugin = new IlpPluginXrpStateless({
  server: 'btp+wss://:secret@localhost:3033',
  secret: 'ss1oM64ccuJuX9utz5pdPRuu5QKMs',
  bandwidth: 1000000
  // address: 'rsxjtFn93z2M4eMyjFaMFiHwzeH1K9xK3K',
  // xrpServer: 'wss://s.altnet.rippletest.net:51233'
})

async function run (sender, receiver) {
  await receiver.connect()
  console.log('receiver connected')

  const receiverSecret = Buffer.from('secret_seed')
  const { sharedSecret, destinationAccount } = ILP.PSK.generateParams({
    destinationAccount: await ILP.ILDCP.getAccount(receiver),
    receiverSecret
  })
  console.log('generated params')

  // Note the user of this module must implement the method for
  // communicating sharedSecret and destinationAccount from the recipient
  // to the sender

  const stopListening = await ILP.PSK.listen(receiver, { receiverSecret }, (params) => {
    console.log('got transfer:', params.transfer)

    console.log('fulfilling.')
    stopListening()
    // return params.fulfill()
    throw new Error('I don\'t like it')
  })

  // the sender can generate these, via the sharedSecret and destinationAccount
  // given to them by the receiver.
  const { packet, condition } = ILP.PSK.createPacketAndCondition({
    sharedSecret,
    destinationAccount,
    destinationAmount: '1000000' // denominated in the ledger's base unit
  })

  console.log('packet', packet)
  console.log('sending quote')

  const quote = await ILP.ILQP.quoteByPacket(sender, packet)
  console.log('got quote:', quote)

  const response = await sender.sendData(IlpPacket.serializeIlpPrepare({
    amount: quote.sourceAmount,
    expiresAt: new Date(Date.now() + 1000 * quote.sourceExpiryDuration),
    executionCondition: condition,
    destination: destinationAccount,
    data: packet
  }))

  if (response[0] === IlpPacket.Type.TYPE_ILP_REJECT) {
    console.log('rejection:', IlpPacket.deserializeIlpReject(response))
  } else if (response[0] === IlpPacket.Type.TYPE_ILP_FULFILL) {
    const fulfillInfo = IlpPacket.deserializeIlpFulfill(response)
    console.log('fulfillment:', fulfillInfo.fulfillment.toString('base64'))
  }

  console.log('transfer sent')
}

run(clientPlugin, serverPlugin)
  .then(() => run(serverPlugin, clientPlugin))
  .catch(err => {
    console.log((typeof err === 'object' && err.stack)
      ? err.stack
      : String(err))
    process.exit(1)
  })
