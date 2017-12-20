const IlpPluginXrpStateless = require('./index.js')
const IlpPacket = require('ilp-packet')
const base64url = require('base64url')
const crypto = require('crypto')
const IlpPluginXrpServer = require('./server.js')
const Store = require('./redisStore.js')

process.on('unhandledRejection', e => {
  console.error(e)
})

const serverPlugin = new IlpPluginXrpServer({
  prefix: 'test.example.',
  port: 3033,
  address: 'r9Ggkrw4VCfRzSqgrkJTeyfZvBvaG9z3hg',
  secret: 'snRHsS3wLzbfeDNSVmtLKjE6sPMws',
  xrpServer: 'wss://s.altnet.rippletest.net:51233',
  _store: new Store(null, 'test.example.')
})

const clientPlugin = new IlpPluginXrpStateless({
  server: 'btp+wss://:secret@localhost:3033',
  secret: 'ss1oM64ccuJuX9utz5pdPRuu5QKMs',
  address: 'rsxjtFn93z2M4eMyjFaMFiHwzeH1K9xK3K',
  xrpServer: 'wss://s.altnet.rippletest.net:51233'
})

async function run () {
  console.log('connecting plugins')
  await serverPlugin.connect()
  await clientPlugin.connect()

  console.log('connected')

  console.log('preparing to send payment client -> server')

  const fulfillment = 'k_XXwP-7L9uaVlU3vVN-zyDKFUtxQdfaE_FgBfyL3X4'
  const fulfillmentBytes = Buffer.from(fulfillment, 'base64')
  const condition = base64url(crypto.createHash('sha256').update(fulfillmentBytes).digest())

  serverPlugin.on('incoming_prepare', async transfer => {
    await serverPlugin.fulfillCondition(transfer.id, fulfillment)
    console.log('fulfilled!')
  })

  await clientPlugin.sendTransfer({
    id: '0928cea4-5871-b31e-86f5-e1d741676a74',
    amount: '10',
    executionCondition: condition,
    expiresAt: new Date(Date.now() + 10 * 1000),
    ilp: IlpPacket.serializeIlpPayment({
      account: serverPlugin.getAccount(),
      amount: '10'
    })
  })
}

run()
  .catch(e => {
    console.error(e)
    process.exit(1)
  })
