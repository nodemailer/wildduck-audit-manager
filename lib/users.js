'use strict';

const config = require('wild-config');
const db = require('./db');
const { encrypt } = require('./tools');
const passwordGenerator = require('generate-password');
const pbkdf2 = require('@phc/pbkdf2');
const { PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST } = require('./consts');
const { ObjectID } = require('mongodb');

class Users {
    constructor() {
        this.pageLimit = config.app.pageLimit;
    }

    init() {}

    async get(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const userData = await db.client.collection('auditusers').findOne({ _id: id, deleted: false, level: { $nin: ['audit', 'group'] } });
        if (!userData) {
            return false;
        }

        return userData;
    }

    async getByUsername(username) {
        const userData = await db.client.collection('auditusers').findOne({ username });
        if (!userData) {
            return false;
        }

        return userData;
    }

    async delete(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client.collection('auditusers').updateOne(
            {
                _id: id,
                deleted: false,
                level: { $nin: ['audit', 'group'] }
            },
            {
                $set: {
                    deleted: true
                }
            }
        );

        return r.modifiedCount;
    }

    async list(page) {
        const query = {
            level: { $nin: ['audit', 'group'] },
            deleted: false
        };

        const count = await db.client.collection('auditusers').countDocuments(query);
        const pages = Math.max(Math.ceil(count / this.pageLimit), 1);
        page = Math.min(page || 1, pages);
        page = Math.max(page, 1);

        const users = await db.client
            .collection('auditusers')
            .find(query)
            .limit(this.pageLimit)
            .skip((page - 1) * this.pageLimit)
            .sort({ _id: -1 })
            .toArray();

        return {
            page,
            pages,
            data: users
        };
    }

    async update(id, updates) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client.collection('auditusers').updateOne(
            {
                _id: id,
                deleted: false,
                level: { $nin: ['audit', 'group'] }
            },
            { $set: updates }
        );

        return r.modifiedCount;
    }

    async resetCredentials(userData) {
        let password;

        // prevent generating passwords with starting = or quote marks
        while (!password || /^=|["']/g.test(password)) {
            password = passwordGenerator.generate({
                length: 30,
                numbers: true,
                symbols: true,
                lowercase: true,
                uppercase: true,
                excludeSimilarCharacters: false,
                strict: true
            });
        }

        let updates = {
            password: await pbkdf2.hash(password, {
                iterations: PDKDF2_ITERATIONS,
                saltSize: PDKDF2_SALT_SIZE,
                digest: PDKDF2_DIGEST
            }),
            passwordUpdated: new Date()
        };

        const text = [
            ['Access URL', 'Username', 'Password', 'Generated'],
            [config.app.adminUrl, userData.username, password, updates.passwordUpdated.toISOString()]
        ];

        let data = text.map(row => row.map(col => `"${(col || '').toString().replace(/"/g, '""')}"`).join(',')).join('\n');
        updates.credentials = await encrypt(userData.pgpPubKey, data);

        return updates;
    }

    async create(values) {
        let password;

        // prevent generating passwords with starting = or quote marks
        while (!password || /^=|["']/g.test(password)) {
            password = passwordGenerator.generate({
                length: 30,
                numbers: true,
                symbols: true,
                lowercase: true,
                uppercase: true,
                excludeSimilarCharacters: false,
                strict: true
            });
        }

        values.password = await pbkdf2.hash(password, {
            iterations: PDKDF2_ITERATIONS,
            saltSize: PDKDF2_SALT_SIZE,
            digest: PDKDF2_DIGEST
        });

        values.created = new Date();

        const text = [
            ['Access URL', 'Username', 'Password', 'Generated'],
            [config.app.adminUrl, values.username, password, values.created.toISOString()]
        ];

        let data = text.map(row => row.map(col => `"${(col || '').toString().replace(/"/g, '""')}"`).join(',')).join('\n');
        values.credentials = await encrypt(values.pgpPubKey, data);

        values.deleted = false;
        values.deletedTime = null;
        values.level = values.level || 'user';

        let r = await db.client.collection('auditusers').insertOne(values);
        return r && r.insertedId;
    }

    async getCredentials(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client.collection('auditusers').findOneAndUpdate(
            {
                _id: id,
                deleted: false,
                level: { $nin: ['audit', 'group'] }
            },
            { $unset: { credentials: true } },
            { returnOriginal: true }
        );

        if (!r || !r.value) {
            return false;
        }

        return r.value;
    }
}

module.exports = new Users();
