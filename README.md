# ILP Plugin XRP Stateless
> An XRP paychan plugin that allows you to be a stateless client


#### Client

- [ ] sign higher version of last claim on outgoing fulfill
- [ ] verify claim on incoming fulfill
- [ ] submit claim on close
- [ ] cache claim somewhere in case of crash
- [ ] load channel balance at connect to determine best claim
- [ ] load cache at connect to determine best claim
- [ ] issue fund transaction when channel is reaching threshold
- [ ] make sure to save channel id with claims so the connector can't refuse to tell you it
- [ ] create outgoing paychan (either automatically or separately as script)

#### Server

- [ ] supply last claim on incoming fulfill
- [ ] verify claim after outgoing fulfill
- [ ] supply channel details as part of info
- [ ] create outgoing paychan if there's an incoming one for certain amount
- [ ] what to do before channel exists for info
