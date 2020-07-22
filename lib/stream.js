'use strict';

const os = require('os');
const db = require('./db');
const config = require('wild-config');

const addToStream = async (user, audit, action, metadata) => {
    let now = new Date();

    let entry = {
        user,
        audit,
        action,
        metadata,
        created: now,
        source: config.app.name,
        host: os.hostname()
    };
    try {
        await db.client.collection('auditstream').insertOne(entry);
    } catch (err) {
        // ignore
    }
};

module.exports = { addToStream };
