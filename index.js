const PluginClient = require('./src/client.js')
const PluginServer = require('./src/server.js')

PluginClient.Server = PluginServer
module.exports = PluginClient
