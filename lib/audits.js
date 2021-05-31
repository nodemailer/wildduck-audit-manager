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
        this.pageLimit = config.app.pageLimit;
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

    getGroupDisplay(groupData) {
        let status;
        let now = new Date();

        if (groupData.expires < now) {
            status = {
                title: 'expired',
                type: 'dark'
            };
        } else if (groupData.start && groupData.start > now) {
            status = {
                title: 'delayed',
                type: 'info'
            };
        } else if (groupData.end && groupData.end < now) {
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

        let addresses = groupData.accounts.map(a => a.address);
        if (addresses.length > 1) {
            let total = addresses.length;
            addresses = addresses.slice(0, 1);
            addresses.push(`+${total - addresses.length}`);
        }

        return {
            name: groupData.name,
            addresses: addresses.join('\n'),
            start: groupData.start ? groupData.start.toISOString() : '',
            end: groupData.end ? groupData.end.toISOString() : '',
            expires: groupData.expires ? groupData.expires.toISOString() : '',

            status
        };
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

        if (auditData.meta && auditData.meta.group) {
            auditData.group = await db.client.collection('auditgroups').findOne({ _id: auditData.meta.group }, { projection: { _id: true, name: true } });
        }

        auditData.display = this.getAuditDisplay(auditData);

        return auditData;
    }

    async getGroup(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const now = new Date();
        const groupData = await db.client.collection('auditgroups').findOne({ _id: id, deleted: false, expires: { $gt: now } });
        if (!groupData) {
            return false;
        }

        groupData.audits = await db.client
            .collection('audits')
            .find({ 'meta.group': groupData._id, deleted: false, expires: { $gt: now } })
            .toArray();

        for (let auditData of groupData.audits) {
            auditData.display = this.getAuditDisplay(auditData);
        }

        groupData.display = this.getGroupDisplay(groupData);

        return groupData;
    }

    async deleteAudit(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client.collection('audits').updateOne({ _id: id, deleted: false }, { $set: { expires: new Date(1) } });
        if (r.modifiedCount) {
            try {
                // mark users as deleted
                await db.client.collection('auditusers').updateMany(
                    {
                        audit: id,
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
            } catch (err) {
                // ignore
            }
        }

        return r.modifiedCount;
    }

    async deleteGroup(id) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }

        const r = await db.client
            .collection('auditgroups')
            .updateOne({ _id: id, deleted: false }, { $set: { expires: new Date(1), deleted: true, deletedTime: new Date() } });

        if (r.modifiedCount) {
            try {
                // mark users as deleted
                await db.client.collection('auditusers').updateMany(
                    {
                        audit: id,
                        deleted: false,
                        level: 'group'
                    },
                    {
                        $set: {
                            deleted: true,
                            deletedTime: new Date()
                        }
                    }
                );
            } catch (err) {
                // ignore
            }
        }

        let audits = await db.client
            .collection('audits')
            .find({ 'meta.group': id, deleted: false }, { projection: { _id: 1 } })
            .toArray();

        for (let { _id: audit } of audits) {
            try {
                // mark users as deleted
                await db.client.collection('auditusers').updateMany(
                    {
                        audit,
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
            } catch (err) {
                // ignore
            }
        }

        await db.client.collection('audits').updateMany(
            { 'meta.group': id, deleted: false },
            {
                $set: {
                    expires: new Date(1)
                    // do not mark deleted:true, otherwise messages are not deleted
                }
            }
        );

        return r.modifiedCount;
    }

    async listGroups(page) {
        const now = new Date();
        const query = { expires: { $gt: now }, deleted: false };

        const count = await db.client.collection('auditgroups').countDocuments(query);
        const pages = Math.max(Math.ceil(count / this.pageLimit), 1);
        page = Math.min(page || 1, pages);
        page = Math.max(page, 1);

        const groups = await db.client
            .collection('auditgroups')
            .find(query)
            .limit(this.pageLimit)
            .skip((page - 1) * this.pageLimit)
            .sort({ _id: -1 })
            .toArray();

        groups.forEach(groupData => {
            groupData.display = this.getGroupDisplay(groupData);
        });

        return {
            page,
            pages,
            data: groups
        };
    }

    async resolveUser(account) {
        return await this.userHandler.asyncGet(account, { username: true, address: true, name: true });
    }

    async createGroup(options) {
        const groupData = Object.assign({ deleted: false }, options, {
            accounts: options.accounts.map(a => ({
                _id: a._id,
                username: a.username,
                name: a.name,
                address: a.address
            }))
        });

        const r = await db.client.collection('auditgroups').insertOne(groupData);

        const group = r && r.insertedId;
        if (!group) {
            throw new Error('Failed to create audit group');
        }

        let results = [];

        for (let account of options.accounts) {
            const auditData = {
                user: account._id,
                start: options.start,
                end: options.end,
                expires: options.expires,
                notes: options.notes,
                meta: {
                    name: account.name,
                    username: account.username,
                    address: account.address,
                    authlog: !!options.meta.authlog,
                    ip: options.meta.ip,
                    createdBy: options.meta.createdBy,
                    created: options.meta.created,
                    group
                }
            };

            try {
                console.log(auditData);
                const audit = await this.create(auditData);
                if (!audit) {
                    throw new Error('Failed to create audit');
                }

                results.push({ success: true, account: account._id, address: account.address, audit });
            } catch (err) {
                results.push({ success: false, account: account._id, address: account.address, err });
            }
        }
        console.log(results);
        return { group, accounts: results };
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

    async updateGroup(id, updates) {
        if (typeof id === 'string') {
            id = new ObjectID(id);
        }
        const r = await db.client.collection('auditgroups').updateOne({ _id: id, deleted: false }, { $set: updates });

        await db.client.collection('audits').updateMany({ 'meta.group': id, deleted: false }, { $set: updates });

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

        let targetData;

        switch (values.level) {
            case 'group':
                targetData = await this.getGroup(values.audit);
                break;
            case 'audit':
            default:
                targetData = await this.get(values.audit);
                break;
        }

        const text = [
            ['Username', 'Password', 'Generated', 'Expires', 'Access URL'],
            [values.username, password, values.created.toISOString(), targetData.expires.toISOString(), config.app.clientUrl]
        ];

        let data = text.map(row => row.map(col => `"${(col || '').toString().replace(/"/g, '""')}"`).join(',')).join('\n');
        values.credentials = await encrypt(values.pgpPubKey, data);

        values.deleted = false;
        values.deletedTime = null;
        values.level = values.level || 'audit';

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
                level: { $in: ['audit', 'group'] }
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
                level: { $in: ['audit', 'group'] }
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
