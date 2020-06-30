'use strict';

const config = require('wild-config');
const mongodb = require('mongodb');
const logger = require('./logger');
const yaml = require('js-yaml');
const fs = require('fs');
const pathlib = require('path');
const setupIndexes = yaml.safeLoad(fs.readFileSync(pathlib.join(__dirname, '..', 'setup', 'indexes.yaml'), 'utf8'));
const Redis = require('ioredis');

const { MongoClient } = mongodb;

module.exports = {
    async connect() {
        const mongoClient = await MongoClient.connect(config.dbs.mongo, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });

        module.exports.connection = mongoClient;
        module.exports.client = mongoClient.db();
        module.exports.redis = new Redis(config.dbs.redis);

        for (const index of setupIndexes.indexes || []) {
            if (index.disabled) {
                continue;
            }
            try {
                await module.exports.client.collection(index.collection).createIndexes([index.index]);
            } catch (err) {
                logger.error({
                    msg: 'Failed to create index',
                    collection: index.collection,
                    index: index.index.name,
                    err
                });
            }
        }
    }
};
