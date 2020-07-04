'use strict';

const express = require('express');
const router = new express.Router();
const { asyncifyRequest, validationErrors, checkPubKey } = require('../../lib/tools');
const audits = require('../../lib/audits');
const Joi = require('@hapi/joi');
const moment = require('moment');
const URL = require('url').URL;

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

        data.listing = await audits.listAudits(page);

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
                daterangeStart: `${now.getFullYear()}/01/01`,
                daterangeEnd: `${now.getFullYear()}/${formatNr(now.getMonth() + 1)}/${formatNr(now.getDate())}`
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
            account: Joi.string().max(256).required().example('admin').label('Account').description('Username or email'),
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

        try {
            const account = await audits.resolveUser(values.account);
            if (!account) {
                return showErrors({ account: 'Unknown account' });
            }

            let start = values.daterangeStart ? moment(values.daterangeStart || now).format('YYYY-MM-DD') + 'T00:00:00Z' : null;
            let end = values.daterangeEnd ? moment(values.daterangeEnd || now).format('YYYY-MM-DD') + 'T23:59:00Z' : null;
            let expires = values.expires ? moment(values.expires || now).format('YYYY-MM-DD') + 'T00:00:00Z' : null;

            console.log({ start, end, expires });

            const data = {
                user: account._id,
                start: start ? new Date(start) : null,
                end: end ? new Date(end) : null,
                expires: expires ? new Date(expires) : null,
                notes: values.notes,
                meta: {
                    name: account.name,
                    username: account.username,
                    address: account.address,
                    authlog: !!values.authlog,
                    ip: req.ip,
                    createdBy: req.user.username,
                    created: new Date()
                }
            };

            console.log(data);
            const audit = await audits.create(data);

            console.log(values);
            console.log(account);
            console.log(audit);

            req.flash('success', 'Account audit was created');
            res.redirect(`/audits?new=${audit}`);
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
            req.flash('danger', 'Invalid audit ID provided');
            return res.redirect('/audits');
        }
        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.id);
        if (!auditData) {
            req.flash('danger', 'Requested audit was not found');
            return res.redirect('/audits');
        }

        let credentials = await audits.listCredentials(auditData._id);

        credentials = credentials.map(credential => {
            if (credential && credential.keyData && credential.keyData.fingerprint) {
                credential.keyData.fingerprint = credential.keyData.fingerprint.split(':').slice(-8).join(':');
            }
            credential.created = credential.created.toISOString();
            return credential;
        });

        if (auditData.meta && auditData.meta.created) {
            auditData.meta.created = auditData.meta.created.toISOString();
        }

        console.log(auditData);
        const data = {
            title: 'Audit',
            mainMenuAudit: true,
            layout: 'layouts/main',

            audit: auditData,
            credentials
        };

        res.render('audits/audit', data);
    })
);

router.get(
    '/audit/:id/edit',
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
            req.flash('danger', 'Invalid audit ID provided');
            return res.redirect('/audits');
        }
        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.id);
        if (!auditData) {
            req.flash('danger', 'Requested audit was not found');
            return res.redirect('/audits');
        }
        const now = new Date();
        auditData.expires = moment(auditData.expires || now).format('YYYY/MM/DD');
        auditData.authlog = !!(auditData.meta && auditData.meta.authlog);

        console.log(auditData);
        const data = {
            title: 'Edit',
            mainMenuAudit: true,
            layout: 'layouts/main',
            audit: auditData,
            values: auditData
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

            const auditData = await audits.get(values.id);
            if (!auditData) {
                req.flash('danger', 'Requested audit was not found');
                return res.redirect('/audits');
            }

            values.expires = moment(values.expires || now).format('YYYY/MM/DD');

            const data = {
                title: 'Create audit',
                mainMenuAudit: true,
                audit: auditData,

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

            const updated = await audits.update(values.id, updates);

            if (updated) {
                req.flash('success', 'Account audit was updated');
            }

            res.redirect(`/audits/audit/${values.id}`);
        } catch (err) {
            req.flash('danger', err.message);
            return showErrors(false, true);
        }
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
            req.flash('danger', 'Invalid audit ID provided');
            return res.redirect('/audits');
        }
        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.id);
        if (!auditData) {
            req.flash('danger', 'Requested audit was not found');
            return res.redirect('/audits');
        }

        console.log(auditData);
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
    '/creds/fetch/:id',
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
            req.flash('danger', 'Invalid credential ID provided');
            return res.redirect('/audits');
        }
        const values = (validationResult && validationResult.value) || {};
        const credentials = await audits.getCredentials(values.id);
        if (!credentials) {
            req.flash('danger', 'Requested credentials were not found');
            return res.redirect('/audits');
        }

        console.log(credentials);

        res.set('Content-Type', 'text/plain');
        res.send(Buffer.from(credentials.credentials));
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
            req.flash('danger', 'Requested audit was not found');
            return res.redirect('/audits');
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
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        console.log(validationResult);

        if (validationResult.error) {
            req.flash('danger', 'Invalid credential ID provided');
            return res.redirect('/audits');
        }
        const values = (validationResult && validationResult.value) || {};
        const credentials = await audits.getCredentials(values.id);
        if (!credentials) {
            req.flash('danger', 'Requested credentials were not found');
            return res.redirect('/audits');
        }

        await audits.deleteCredentials(values.id);
        req.flash('success', 'Credentials deleted');
        return res.redirect(`/audits/audit/${credentials.audit}`);
    })
);

router.post(
    '/delete',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('Audit ID')
        });

        const validationResult = auditListingSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            req.flash('danger', 'Invalid audit ID provided');
            return res.redirect('/audits');
        }
        const values = (validationResult && validationResult.value) || {};
        const auditData = await audits.get(values.id);
        if (!auditData) {
            req.flash('danger', 'Requested audit was not found');
            return res.redirect('/audits');
        }

        await audits.deleteAudit(values.id);
        req.flash('success', 'Audit deleted');
        return res.redirect(`/audits`);
    })
);

module.exports = router;
