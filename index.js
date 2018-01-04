const PluginClient = require('./src/client.js')
const PluginServer = require('./src/server.js')

PluginServer.Client = PluginClient
module.exports = PluginServer
