# ILP Plugin XRP Asym
> An XRP paychan plugin allowing for a server that takes many connections and a
> lightweight client

```js
const IlpPluginXrpAsym = require('ilp-plugin-xrp-asym')

const serverPlugin = new IlpPluginXrpAsym.Server({
  // Port on which to listen
  port: 6666,

  // XRP credentials of the server
  address: 'rKzfaLjeVZXasCSU2heTUGw9VhQmFNSd8k',
  secret: 'snHNnoL6S67wNvydcZg9y9bFzPZwG',

  // Rippled server for the server to use
  xrpServer: 'wss://s.altnet.rippletest.net:51233',

  // Max amount to be unsecured at any one time
  bandwidth: 1000000,

  // Persistent Key-value store. ILP-Connector will pass
  // this parameter in automatically.
  _store: new Store()
})

const clientPlugin = new IlpPluginXrpAsym({
  // The BTP address of the asymmetric server plugin. The `btp_secret`
  // in here is hashed to become the account name. Note that if you switch
  // XRP accounts, you also have to switch `btp_secret`s
  server: 'btp+ws://:btp_secret@localhost:6666',

  // Rippled server for client use
  xrpServer: 'wss://s.altnet.rippletest.net:51233'

  // XRP secret. The address can be dynamically determined from this,
  // or can be specified as a separate option.
  secret: 'ss1oM64ccuJuX9utz5pdPRuu5QKMs'
})
```

#### Client

- [x] sign higher version of last claim on outgoing fulfill
- [x] verify claim on incoming fulfill
- [x] verify channel details on connect
- [x] submit claim on close
- [x] cache claim somewhere in case of crash
- [x] load channel balance at connect to determine best claim
- [x] load cache at connect to determine best claim
- [x] issue fund transaction when channel is reaching threshold
- [x] make sure to save channel id with claims so the connector can't refuse to tell you it
- [x] create outgoing paychan (either automatically or separately as script)
- [x] refactor shared functions into utils
- [x] watch for channel close or details changing
- [x] accept message telling you to refresh channel so that you see fund tx's
- [x] tell server to refresh details on fund

#### Server

- [x] supply last claim on incoming fulfill
- [x] verify claim after outgoing fulfill
- [x] supply channel details as part of info
- [x] create outgoing paychan if there's an incoming one for certain amount
- [x] what to do before channel exists for info
- [x] watch for channel close
- [x] fund tx for outgoing channel above threshold
- [x] tell client to refresh details after fund (or maybe automatically refreshing will be ok)
