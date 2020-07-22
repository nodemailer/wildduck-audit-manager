'use strict';

const os = require('os');
const db = require('./db');
const config = require('wild-config');

const pageLimit = config.app.pageLimit;

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

const formatStreamEntry = entryData => {
    let display = {
        ip: entryData.metadata.ip,
        created: entryData.created.toISOString()
    };
    switch (entryData.action) {
        case 'create_user':
            display.action = {
                name: 'Create user',
                key: entryData.action
            };
            break;
        case 'delete_user':
            display.action = {
                name: 'Delete user',
                key: entryData.action
            };
            break;
        case 'create_audit':
            display.action = {
                name: 'Create audit',
                key: entryData.action
            };
            break;
        case 'edit_audit':
            display.action = {
                name: 'Edit audit',
                key: entryData.action
            };
            break;
        default:
            display.action = {
                name: entryData.action.replace(/_/g, ' ').replace(/^./, c => c.toUpperCase(c)),
                key: entryData.action
            };
    }
    if (entryData.metadata.keyData) {
        display.keyData = {
            name: entryData.metadata.keyData.name,
            address: entryData.metadata.keyData.address,
            fingerprint: entryData.metadata.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase()
        };
    }

    if (entryData.metadata.owner) {
        display.owner = entryData.metadata.owner;
    }

    return display;
};

const list = async (query, page) => {
    const count = await db.client.collection('auditstream').countDocuments(query);
    const pages = Math.max(Math.ceil(count / pageLimit), 1);
    page = Math.min(page || 1, pages);
    page = Math.max(page, 1);

    const entries = await db.client
        .collection('auditstream')
        .find(query)
        .limit(pageLimit)
        .skip((page - 1) * pageLimit)
        .sort({ _id: -1 })
        .toArray();

    entries.forEach(entryData => {
        entryData.display = formatStreamEntry(entryData);
    });
    console.log(entries);
    return {
        page,
        pages,
        data: entries
    };
};

module.exports = { addToStream, list };
