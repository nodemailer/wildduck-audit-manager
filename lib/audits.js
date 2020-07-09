'use strict';

const config = require('wild-config');
const db = require('./db');
const logger = require('./logger').child('audit');
const { encrypt } = require('./tools');
const UserHandler = require('wildduck/lib/user-handler');
const AuditHandler = require('wildduck/lib/audit-handler');
const passwordGenerator = require('generate-password');
const pbkdf2 = require('@phc/pbkdf2');
const { PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST } = require('./consts');
const { ObjectID } = require('mongodb');

class Audits {
    constructor() {
        this.pageLimit = 20;
    }

    init() {
        this.auditHandler = new AuditHandler({
            database: db.client,
            users: db.users,
            gridfs: db.gridfs,
            bucket: 'audit',
            loggelf: message => logger.info(message)
        });

        this.userHandler = new UserHandler({
            database: db.client,
            users: db.users,
            gridfs: db.gridfs,
            redis: db.redis,
            loggelf: message => logger.info(message)
        });
    }

    getAuditDisplay(auditData) {
        let name = (auditData.userData && auditData.userData.name) || (auditData.meta && (auditData.meta.name || auditData.meta.username));
        let address = (auditData.userData && auditData.userData.address) || (auditData.meta && auditData.meta.address);

        let status;
        let now = new Date();
        switch (auditData.import.status) {
            case 'queued':
            case 'importing':
                status = {
                    title: 'preparing',
                    type: 'light'
                };
                break;
            default:
                if (auditData.expires < now) {
                    status = {
                        title: 'expired',
                        type: 'dark'
                    };
                } else if (auditData.start && auditData.start > now) {
                    status = {
                        title: 'delayed',
                        type: 'info'
                    };
                } else if (auditData.end && auditData.end < now) {
                    status = {
                        title: 'stopped',
                        type: 'secondary'
                    };
                } else {
                    status = {
                        title: 'enabled',
                        type: 'success'
                    };
                }

                break;
        }

        return {
            name: name || address,
            address,
            username: (auditData.userData && auditData.userData.username) || (auditData.meta && auditData.meta.username),
            start: auditData.start ? auditData.start.toISOString() : '',
            end: auditData.end ? auditData.end.toISOString() : '',
            expires: auditData.expires ? auditData.expires.toISOString() : '',

            status
        };
    }

    async get(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const now = new Date();
        const auditData = await db.client.collection('audits').findOne({ _id: id, deleted: false, expires: { $gt: now } });
        if (!auditData) {
            return false;
        }
        let userData = await db.users
            .collection('users')
            .findOne({ _id: auditData.user }, { projection: { _id: true, username: true, name: true, address: true } });
        if (userData) {
            auditData.userData = userData;
        }

        auditData.display = this.getAuditDisplay(auditData);

        return auditData;
    }

    async deleteAudit(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }
        const r = await db.client.collection('audits').updateOne({ _id: id, deleted: false }, { $set: { expires: new Date(1) } });

        return r.modifiedCount;
    }

    async listAudits(page) {
        const now = new Date();
        const query = { expires: { $gt: now }, deleted: false };

        const count = await db.client.collection('audits').countDocuments(query);
        const pages = Math.max(Math.ceil(count / this.pageLimit), 1);
        page = Math.min(page || 1, pages);
        page = Math.max(page, 1);

        const audits = await db.client
            .collection('audits')
            .find(query)
            .limit(this.pageLimit)
            .skip((page - 1) * this.pageLimit)
            .sort({ _id: -1 })
            .toArray();

        const uniqueUsers = new Map();
        audits.forEach(auditData => {
            const userStr = auditData.user.toString();
            if (uniqueUsers.has(userStr)) {
                uniqueUsers.get(userStr).push(auditData);
            } else {
                uniqueUsers.set(userStr, [auditData]);
            }
        });

        if (uniqueUsers.size) {
            let userList = Array.from(uniqueUsers.values()).map(list => list[0].user);

            let users = await db.users
                .collection('users')
                .find({ _id: { $in: userList } })
                .project({ _id: true, username: true, name: true, address: true })
                .toArray();

            for (let userData of users) {
                const userStr = userData._id.toString();
                if (uniqueUsers.has(userStr)) {
                    uniqueUsers.get(userStr).forEach(auditData => {
                        auditData.userData = userData;
                    });
                }
            }
        }

        audits.forEach(auditData => {
            auditData.display = this.getAuditDisplay(auditData);
        });

        return {
            page,
            pages,
            data: audits
        };
    }

    async resolveUser(account) {
        return await this.userHandler.asyncGet(account, { username: true, address: true, name: true });
    }

    async create(options) {
        return this.auditHandler.create(options);
    }

    async update(id, updates) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }
        const r = await db.client.collection('audits').updateOne({ _id: id, deleted: false }, { $set: updates });

        return r.modifiedCount;
    }

    async createCredentials(values) {
        values.audit = new ObjectID(values.audit);
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

        values.username =
            'audit.' +
            passwordGenerator.generate({
                length: 12,
                numbers: true,
                lowercase: true,
                uppercase: false,
                symbols: false,
                excludeSimilarCharacters: false,
                strict: false
            });

        values.password = await pbkdf2.hash(password, {
            iterations: PDKDF2_ITERATIONS,
            saltSize: PDKDF2_SALT_SIZE,
            digest: PDKDF2_DIGEST
        });

        values.created = new Date();

        const auditData = await this.get(values.audit);
        const text = [
            ['Audited account', 'Access URL', 'Username', 'Password', 'Generated', 'Expires'],
            [auditData.display.address, config.app.clientUrl, values.username, password, values.created.toISOString(), auditData.expires.toISOString()]
        ];

        let data = text.map(row => row.map(col => `"${(col || '').toString().replace(/"/g, '""')}"`).join(',')).join('\n');
        values.credentials = await encrypt(values.pgpPubKey, data);

        values.deleted = false;
        values.deletedTime = null;
        values.level = 'audit';

        let r = await db.client.collection('auditusers').insertOne(values);
        return r && r.insertedId;
    }

    async listCredentials(audit) {
        return await db.client
            .collection('auditusers')
            .find({
                audit,
                deleted: false
            })
            .sort({ _id: 1 })
            .toArray();
    }

    async getCredentials(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client.collection('auditusers').findOneAndUpdate(
            {
                _id: id,
                deleted: false,
                level: 'audit'
            },
            { $unset: { credentials: true } },
            { returnOriginal: true }
        );

        if (!r || !r.value) {
            return false;
        }

        return r.value;
    }

    async deleteCredentials(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client.collection('auditusers').updateOne(
            {
                _id: id,
                deleted: false,
                level: 'audit'
            },
            {
                $set: {
                    deleted: true,
                    deletedTime: new Date()
                }
            }
        );

        return r.modifiedCount;
    }
}

module.exports = new Audits();
