'use strict';

const express = require('express');
const router = new express.Router();
const { asyncifyRequest, validationErrors, checkPubKey, signFinger, signPubKey } = require('../../lib/tools');
const audits = require('../../lib/audits');
const Joi = require('@hapi/joi');
const moment = require('moment');
const URL = require('url').URL;
const { addToStream } = require('../../lib/stream');
const { ObjectID } = require('mongodb');

router.get(
    '/',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            p: Joi.number()
                .empty('')
                .min(1)
                .max(64 * 1024)
                .default(1)
                .example(1)
                .label('Page Number')
        });

        const validationResult = auditListingSchema.validate(req.query, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = validationResult && validationResult.value;
        const page = values && !validationResult.error ? values.p : 0;

        const data = {
            title: 'Audits',
            mainMenuAudit: true,
            layout: 'layouts/main'
        };

        data.listing = await audits.listGroups(page);

        if (data.listing.page < data.listing.pages) {
            let url = new URL('audits', 'http://localhost');
            url.searchParams.append('p', data.listing.page + 1);
            data.nextPage = url.pathname + (url.search ? url.search : '');
        }

        if (data.listing.page > 1) {
            let url = new URL('audits', 'http://localhost');
            url.searchParams.append('p', data.listing.page - 1);
            data.previousPage = url.pathname + (url.search ? url.search : '');
        }

        res.render('audits/index', data);
    })
);

router.get(
    '/signPubKey/:key',
    asyncifyRequest(async (req, res) => {
        res.set('Content-Type', 'text/plain');
        res.setHeader('Content-disposition', `attachment; filename=${signFinger()}.asc`);
        res.send(Buffer.from(signPubKey()));
    })
);

router.get(
    '/new',
    asyncifyRequest(async (req, res) => {
        const now = new Date();
        const formatNr = nr => {
            nr = nr.toString();
            if (nr.length < 2) {
                nr = '0' + nr;
            }
            return nr;
        };

        const data = {
            title: 'Create audit',
            mainMenuAudit: true,

            values: {
                expires: `${now.getFullYear()}/12/31`,
                daterangeStart: `1970/01/01`,
                daterangeEnd: `${now.getFullYear() + 1}/${formatNr(now.getMonth() + 1)}/${formatNr(now.getDate())}`
            },

            layout: 'layouts/main'
        };

        res.render('audits/new', data);
    })
);

router.post(
    '/new',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            name: Joi.string().empty('').max(256).trim().required().example('New audit').label('AuditName').description('Audit name'),
            accounts: Joi.string()
                .empty('')
                .max(1024 * 1024)
                .trim()
                .required()
                .example('admin')
                .label('Accounts')
                .description('List of usernames or email addresses'),

            daterangeStart: Joi.date().example('2020/01/02').label('Start date').description('Start date'),
            daterangeEnd: Joi.date().greater(Joi.ref('daterangeStart')).example('2020/01/02').label('End date').description('End date'),
            expires: Joi.date().greater('now').example('2020/01/02').label('Expiration date').description('Expiration date'),
            authlog: Joi.boolean()
                .truthy('Y', 'true', '1', 'on')
                .default(false)
                .label('Authentiation log')
                .description('Include authnetication log as part of the audit'),
            notes: Joi.string().empty('').trim().required().label('Notes').description('Reason for creating an audit')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const now = new Date();
        const values = (validationResult && validationResult.value) || {};

        let showErrors = (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to create account audit');
            }

            values.daterangeStart = moment(values.daterangeStart || now).format('YYYY/MM/DD');
            values.daterangeEnd = moment(values.daterangeEnd || now).format('YYYY/MM/DD');
            values.expires = moment(values.expires || now).format('YYYY/MM/DD');

            const data = {
                title: 'Create audit',
                mainMenuAudit: true,

                values,
                errors,

                layout: 'layouts/main'
            };

            res.render('audits/new', data);
        };

        if (validationResult.error) {
            let errors = validationErrors(validationResult);
            if (errors.daterangeStart) {
                errors.daterange = errors.daterangeStart;
            } else if (errors.daterangeEnd) {
                errors.daterange = errors.daterangeEnd;
            }
            return showErrors(errors);
        }

        let accounts = (values.accounts || '')
            .split(/[,\n]/)
            .map(a => a.trim())
            .filter(a => a);

        let accountIds = new Set();
        let accountList = [];
        let failedAccounts = [];

        for (let username of accounts) {
            try {
                const account = await audits.resolveUser(username);
                if (!account) {
                    // check for deleted
                    const deletedAccount = await audits.resolveDeletedUser(username);

                    console.log('got deleted accoubt', deletedAccount);

                    if (!deletedAccount) {
                        failedAccounts.push(`${username}: unknown`);
                    } else if (!accountIds.has(deletedAccount._id.toString())) {
                        accountList.push(deletedAccount);
                        accountIds.add(deletedAccount._id.toString());
                    }
                } else if (!accountIds.has(account._id.toString())) {
                    accountList.push(account);
                    accountIds.add(account._id.toString());
                }
            } catch (err) {
                failedAccounts.push(`${username}: ${err.message}`);
            }
        }

        if (!accounts.length) {
            failedAccounts.push(`no accounts provided`);
        }

        if (failedAccounts.length) {
            return showErrors({ accounts: failedAccounts.join(', ') });
        }

        let start = values.daterangeStart ? moment(values.daterangeStart || now).format('YYYY-MM-DD') + 'T00:00:00Z' : null;
        let end = values.daterangeEnd ? moment(values.daterangeEnd || now).format('YYYY-MM-DD') + 'T23:59:00Z' : null;
        let expires = values.expires ? moment(values.expires || now).format('YYYY-MM-DD') + 'T00:00:00Z' : null;

        const groupData = {
            name: values.name,
            accounts: accountList,
            start: start ? new Date(start) : null,
            end: end ? new Date(end) : null,
            expires: expires ? new Date(expires) : null,
            notes: values.notes,
            meta: {
                authlog: !!values.authlog,
                ip: req.ip,
                createdBy: req.user.username,
                createdById: req.user._id,
                createdByName: req.user.name,
                created: new Date()
            }
        };

        try {
            const result = await audits.createGroup(groupData);

            await addToStream(
                req.user._id || req.user.username,
                result.group,
                'create_audit_group',
                Object.assign(
                    {
                        owner: {
                            _id: req.user._id,
                            username: req.user.username,
                            name: req.user.name
                        },
                        auditAccounts: accountList,
                        ip: req.ip
                    },
                    values
                )
            );

            req.flash('success', 'Account audit was created');
            res.redirect(`/audits?new=${result.group}`);
        } catch (err) {
            req.flash('danger', err.message);
            return showErrors(false, true);
        }
    })
);

router.get(
    '/audit/:id',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid audit ID provided');
            err.status = 422;
            throw err;
        }
        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.id);
        if (!auditData) {
            let err = new Error('Requested audit was not found');
            err.status = 404;
            throw err;
        }

        let credentials = await audits.listCredentials(auditData._id);

        credentials = credentials.map(credential => {
            if (credential && credential.keyData && credential.keyData.fingerprint) {
                credential.keyData.fingerprint = credential.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase();
            }
            credential.created = credential.created.toISOString();
            return credential;
        });

        if (auditData.meta && auditData.meta.created) {
            auditData.meta.created = auditData.meta.created.toISOString();
        }

        const data = {
            title: 'Audit',
            mainMenuAudit: true,
            layout: 'layouts/main',

            audit: auditData,
            credentials,
            signFinger: signFinger()
        };

        res.render('audits/audit', data);
    })
);

const groupRouteHandler = async (req, res) => {
    let auditListingSchema = Joi.object({
        id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
    });

    const validationResult = auditListingSchema.validate(req.params, {
        stripUnknown: true,
        abortEarly: false,
        convert: true
    });

    if (validationResult.error) {
        let err = new Error('Invalid audit ID provided');
        err.status = 422;
        throw err;
    }
    const values = (validationResult && validationResult.value) || {};
    const groupData = await audits.getGroup(values.id);
    if (!groupData) {
        let err = new Error('Requested audit was not found');
        err.status = 404;
        throw err;
    }

    let credentials = await audits.listCredentials(groupData._id);

    credentials = credentials.map(credential => {
        if (credential && credential.keyData && credential.keyData.fingerprint) {
            credential.keyData.fingerprint = credential.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase();
        }
        credential.created = credential.created.toISOString();
        return credential;
    });

    if (groupData.meta && groupData.meta.created) {
        groupData.meta.created = groupData.meta.created.toISOString();
    }

    const data = {
        title: 'Audit',
        mainMenuAudit: true,
        layout: 'layouts/main',

        group: groupData,
        credentials,

        credentialsCount: credentials.length,

        signFinger: signFinger()
    };

    res.render('audits/group', data);
};

router.get(
    '/group/:id',
    asyncifyRequest(async (req, res) => {
        res.locals.accountsTab = true;
        return groupRouteHandler(req, res);
    })
);

router.get(
    '/group/:id/accounts',
    asyncifyRequest(async (req, res) => {
        res.locals.accountsTab = true;
        return groupRouteHandler(req, res);
    })
);

router.get(
    '/group/:id/credentials',
    asyncifyRequest(async (req, res) => {
        res.locals.credentialsTab = true;
        return groupRouteHandler(req, res);
    })
);

router.get(
    '/group/:id/edit',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid audit ID provided');
            err.status = 422;
            throw err;
        }
        const values = (validationResult && validationResult.value) || {};
        const groupData = await audits.getGroup(values.id);
        if (!groupData) {
            let err = new Error('Requested audit was not found');
            err.status = 404;
            throw err;
        }
        const now = new Date();
        groupData.expires = moment(groupData.expires || now).format('YYYY/MM/DD');
        groupData.authlog = !!(groupData.meta && groupData.meta.authlog);

        const data = {
            title: 'Edit',
            mainMenuAudit: true,
            layout: 'layouts/main',
            group: groupData,
            values: groupData
        };

        res.render('audits/edit', data);
    })
);

router.post(
    '/edit',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID'),
            expires: Joi.date().greater('now').example('2020/01/02').label('Expiration date').description('Expiration date'),
            authlog: Joi.boolean()
                .truthy('Y', 'true', '1', 'on')
                .default(false)
                .label('Authentiation log')
                .description('Include authnetication log as part of the audit')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const now = new Date();
        const values = (validationResult && validationResult.value) || {};

        let showErrors = async (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to create account audit');
            }

            const groupData = await audits.getGroup(values.id);
            if (!groupData) {
                let err = new Error('Requested audit was not found');
                err.status = 404;
                throw err;
            }

            values.expires = moment(values.expires || now).format('YYYY/MM/DD');

            const data = {
                title: 'Edit',
                mainMenuAudit: true,
                group: groupData,

                values,
                errors,

                layout: 'layouts/main'
            };

            res.render('audits/edit', data);
        };

        if (validationResult.error) {
            let errors = validationErrors(validationResult);
            return showErrors(errors);
        }

        try {
            let expires = values.expires ? moment(values.expires || now).format('YYYY-MM-DD') + 'T00:00:00Z' : null;

            const updates = {
                expires: expires ? new Date(expires) : null,
                'meta.authlog': values.authlog
            };

            const updated = await audits.updateGroup(values.id, updates);

            if (updated) {
                req.flash('success', 'Audit settings were updated');

                await addToStream(
                    req.user._id || req.user.username,
                    new ObjectID(values.id),
                    'edit_audit_group',
                    Object.assign(
                        {
                            owner: {
                                _id: req.user._id,
                                username: req.user.username,
                                name: req.user.name
                            },
                            ip: req.ip
                        },
                        values
                    )
                );
            }

            res.redirect(`/audits/group/${values.id}`);
        } catch (err) {
            req.flash('danger', err.message);
            return showErrors(false, true);
        }
    })
);

router.get(
    '/group/:id/creds/new',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid audit ID provided');
            err.status = 422;
            throw err;
        }
        const values = (validationResult && validationResult.value) || {};
        const groupData = await audits.getGroup(values.id);
        if (!groupData) {
            let err = new Error('Requested audit was not found');
            err.status = 404;
            throw err;
        }

        const data = {
            title: 'Create credentials',
            mainMenuAudit: true,
            layout: 'layouts/main',

            group: groupData
        };

        res.render('audits/creds/group-new', data);
    })
);

router.get(
    '/audit/:id/creds/new',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid audit ID provided');
            err.status = 422;
            throw err;
        }
        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.id);
        if (!auditData) {
            let err = new Error('Requested audit was not found');
            err.status = 404;
            throw err;
        }

        const data = {
            title: 'Create credentials',
            mainMenuAudit: true,
            layout: 'layouts/main',

            audit: auditData
        };

        res.render('audits/creds/new', data);
    })
);

router.get(
    '/creds/fetch/:id/credentials.csv.gpg',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid credentials ID provided');
            err.status = 422;
            throw err;
        }
        const values = (validationResult && validationResult.value) || {};
        const credentials = await audits.getCredentials(values.id);
        if (!credentials || !credentials.credentials) {
            let err = new Error('Requested credentials were not found');
            err.status = 404;
            throw err;
        }

        await addToStream(
            req.user._id || req.user.username,
            new ObjectID(values.id),
            'fetch_audit_creds',
            Object.assign(
                {
                    owner: {
                        _id: req.user._id,
                        username: req.user.username,
                        name: req.user.name
                    },
                    ip: req.ip
                },
                values
            )
        );

        res.set('Content-Type', 'text/plain');
        res.setHeader('Content-disposition', 'attachment; filename=credentials.csv.gpg');
        res.send(Buffer.from(credentials.credentials));
    })
);

router.get(
    '/creds/pubkey/:id/:key',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid credentials ID provided');
            err.status = 422;
            throw err;
        }

        const values = (validationResult && validationResult.value) || {};
        const credentials = await audits.getCredentialDetails(values.id);
        if (!credentials || !credentials.pgpPubKey || !credentials.keyData) {
            let err = new Error('Requested credentials were not found');
            err.status = 404;
            throw err;
        }

        res.set('Content-Type', 'text/plain');
        res.setHeader('Content-disposition', `attachment; filename=${credentials.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase()}.asc`);
        res.send(Buffer.from(credentials.pgpPubKey));
    })
);

router.post(
    '/creds/group-new',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            group: Joi.string().empty('').hex().length(24).required().label('Audit ID'),
            name: Joi.string().max(256).required().example('admin').label('Name').description('Name of the credentials holder'),
            email: Joi.string().email().required().example('admin@example.com').label('Email').description('Email of the credentials holder'),
            pgpPubKey: Joi.string()
                .empty('')
                .trim()
                .max(65 * 1024)
                .required()
                .label('PGP Public Key')
                .description('Public key for encryption'),
            notes: Joi.string().empty('').trim().required().label('Notes').description('Reason for creating an audit')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = (validationResult && validationResult.value) || {};
        const groupData = await audits.getGroup(values.group);
        if (!groupData) {
            let err = new Error('Requested audit was not found');
            err.status = 404;
            throw err;
        }

        let showErrors = async (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to create credentials');
            }

            const data = {
                title: 'Create credentials',
                mainMenuAudit: true,
                layout: 'layouts/main',

                group: groupData,

                values,
                errors
            };
            res.render('audits/creds/group-new', data);
        };

        if (validationResult.error) {
            let errors = validationErrors(validationResult);
            return await showErrors(errors);
        }

        const credsData = {
            audit: values.group,
            level: 'group',
            name: values.name,
            email: values.email,
            pgpPubKey: values.pgpPubKey,
            notes: values.notes,
            ip: req.ip,
            createdBy: req.user.username
        };

        try {
            credsData.keyData = await checkPubKey(values.pgpPubKey);
        } catch (err) {
            return await showErrors({
                pgpPubKey: 'PGP key validation failed. ' + err.message
            });
        }

        try {
            const creds = await audits.createCredentials(credsData);

            if (creds) {
                req.flash('success', 'Credentials created');

                await addToStream(
                    req.user._id || req.user.username,
                    new ObjectID(values.group),
                    'create_audit_creds_group',
                    Object.assign(
                        {
                            owner: {
                                _id: req.user._id,
                                username: req.user.username,
                                name: req.user.name
                            },
                            ip: req.ip,
                            keyData: credsData.keyData
                        },
                        values
                    )
                );

                return res.redirect(`/audits/group/${values.group}/credentials?created_creds=${creds}`);
            } else {
                throw new Error('Credentials were not created');
            }
        } catch (err) {
            req.flash('danger', 'Failed to create credentials');
            return showErrors(false, false);
        }
    })
);

router.post(
    '/creds/new',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            audit: Joi.string().empty('').hex().length(24).required().label('Audit ID'),
            name: Joi.string().max(256).required().example('admin').label('Name').description('Name of the credentials holder'),
            email: Joi.string().email().required().example('admin@example.com').label('Email').description('Email of the credentials holder'),
            pgpPubKey: Joi.string()
                .empty('')
                .trim()
                .max(65 * 1024)
                .required()
                .label('PGP Public Key')
                .description('Public key for encryption'),
            notes: Joi.string().empty('').trim().required().label('Notes').description('Reason for creating an audit')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.audit);
        if (!auditData) {
            let err = new Error('Requested audit was not found');
            err.status = 404;
            throw err;
        }

        let showErrors = async (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to create credentials');
            }

            const data = {
                title: 'Create credentials',
                mainMenuAudit: true,
                layout: 'layouts/main',

                audit: auditData,

                values,
                errors
            };
            res.render('audits/creds/new', data);
        };

        if (validationResult.error) {
            let errors = validationErrors(validationResult);
            return await showErrors(errors);
        }

        try {
            values.keyData = await checkPubKey(values.pgpPubKey);
        } catch (err) {
            return await showErrors({
                pgpPubKey: 'PGP key validation failed. ' + err.message
            });
        }

        values.ip = req.ip;
        values.createdBy = req.user.username;
        try {
            const creds = await audits.createCredentials(values);

            if (creds) {
                req.flash('success', 'Credentials created');

                await addToStream(
                    req.user._id || req.user.username,
                    new ObjectID(values.audit),
                    'create_audit_creds',
                    Object.assign(
                        {
                            owner: {
                                _id: req.user._id,
                                username: req.user.username,
                                name: req.user.name
                            },
                            ip: req.ip
                        },
                        values
                    )
                );

                return res.redirect(`/audits/audit/${values.audit}?created_creds=${creds}`);
            } else {
                throw new Error('Credentials were not created');
            }
        } catch (err) {
            req.flash('danger', 'Failed to create credentials');
            return showErrors(false, false);
        }
    })
);

router.post(
    '/creds/delete',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID'),
            type: Joi.string().empty('').allow('group', 'audit').required().label('Entry type')
        });

        const validationResult = auditListingSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid credentials ID provided');
            err.status = 422;
            throw err;
        }

        const values = (validationResult && validationResult.value) || {};
        const credentials = await audits.getCredentials(values.id);
        if (!credentials) {
            let err = new Error('Requested credentials were not found');
            err.status = 404;
            throw err;
        }

        await audits.deleteCredentials(values.id);

        await addToStream(
            req.user._id || req.user.username,
            credentials._id,
            'delete_audit_creds',
            Object.assign(
                {
                    owner: {
                        _id: req.user._id,
                        username: req.user.username,
                        name: req.user.name
                    },
                    ip: req.ip
                },
                values
            )
        );

        req.flash('success', 'Credentials deleted');
        return res.redirect(`/audits/${values.type}/${credentials.audit}/credentials`);
    })
);

router.post(
    '/delete',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID'),
            type: Joi.string().empty('').allow('group', 'audit').required().label('Entry type')
        });

        const validationResult = auditListingSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid audit ID provided');
            err.status = 422;
            throw err;
        }
        const values = (validationResult && validationResult.value) || {};

        switch (values.type) {
            case 'audit':
                {
                    const auditData = await audits.get(values.id);
                    if (!auditData) {
                        let err = new Error('Requested audit was not found');
                        err.status = 404;
                        throw err;
                    }

                    await audits.deleteAudit(values.id);

                    await addToStream(
                        req.user._id || req.user.username,
                        auditData._id,
                        'delete_audit',
                        Object.assign(
                            {
                                owner: {
                                    _id: req.user._id,
                                    username: req.user.username,
                                    name: req.user.name
                                },
                                ip: req.ip
                            },
                            values
                        )
                    );
                }
                break;

            case 'group':
                {
                    const groupData = await audits.getGroup(values.id);
                    if (!groupData) {
                        let err = new Error('Requested audit was not found');
                        err.status = 404;
                        throw err;
                    }

                    await audits.deleteGroup(values.id);

                    await addToStream(
                        req.user._id || req.user.username,
                        groupData._id,
                        'delete_audit_group',
                        Object.assign(
                            {
                                owner: {
                                    _id: req.user._id,
                                    username: req.user.username,
                                    name: req.user.name
                                },
                                ip: req.ip
                            },
                            values
                        )
                    );
                }
                break;
        }

        req.flash('success', 'Audit deleted');
        return res.redirect(`/audits`);
    })
);

module.exports = router;
