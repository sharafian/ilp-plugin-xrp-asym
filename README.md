# ILP Plugin XRP Stateless
> An XRP paychan plugin that allows you to be a stateless client

```js
const plugin = new IlpPluginXrpStateless({
  server: 'btp+wss://:secret@example.com',
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
- [ ] watch for channel close or details changing
- [x] accept message telling you to refresh channel so that you see fund tx's
- [x] tell server to refresh details on fund

#### Server

- [x] supply last claim on incoming fulfill
- [x] verify claim after outgoing fulfill
- [x] supply channel details as part of info
- [x] create outgoing paychan if there's an incoming one for certain amount
- [x] what to do before channel exists for info
- [ ] watch for channel close
- [x] fund tx for outgoing channel above threshold
- [x] tell client to refresh details after fund (or maybe automatically refreshing will be ok)
