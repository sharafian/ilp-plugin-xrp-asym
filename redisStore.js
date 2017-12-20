const Redis = require('ioredis')

class RedisStore {
  constructor (uri, name) {
    this.name = name
    this.redis = new Redis({ keyPrefix: 'ilp:' + name + ':' })
  }

  async get (key) {
    return this.redis.get(key) || undefined
  }

  async put (key, value) {
    return this.redis.pipeline()
      .set(key, String(value))
      .publish('ilp:' + this.name + ':' + key, value)
      .exec()
  }

  async del (key) {
    return this.redis.pipeline()
      .del(key)
      .publish('ilp:' + this.name + ':' + key, '')
      .exec()
  }
}

module.exports = RedisStore
