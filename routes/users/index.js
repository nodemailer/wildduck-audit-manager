'use strict';

const express = require('express');
const router = new express.Router();
const { asyncifyRequest, validationErrors, checkPubKey, signFinger } = require('../../lib/tools');
const users = require('../../lib/users');
const Joi = require('@hapi/joi');
const URL = require('url').URL;
const { addToStream } = require('../../lib/stream');
const config = require('wild-config');

const levels = [
    { level: 'user', name: 'User', color: 'secondary' },
    { level: 'admin', name: 'Administrator', color: 'info' }
];

router.get(
    '/',
    asyncifyRequest(async (req, res) => {
        let listingSchema = Joi.object({
            p: Joi.number()
                .empty('')
                .min(1)
                .max(64 * 1024)
                .default(1)
                .example(1)
                .label('Page Number')
        });

        const validationResult = listingSchema.validate(req.query, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = validationResult && validationResult.value;
        const page = values && !validationResult.error ? values.p : 0;

        const data = {
            title: 'Users',
            mainMenuUsers: true,
            layout: 'layouts/main',

            signFinger: signFinger()
        };

        data.listing = await users.list(page);

        data.listing.data.forEach(userData => {
            if (userData && userData.keyData && userData.keyData.fingerprint) {
                userData.keyData.fingerprint = userData.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase();
            }
            let level = levels.find(level => userData.level === level.level);
            if (level) {
                userData.label = level;
            }
        });

        if (data.listing.page < data.listing.pages) {
            let url = new URL('users', 'http://localhost');
            url.searchParams.append('p', data.listing.page + 1);
            data.nextPage = url.pathname + (url.search ? url.search : '');
        }

        if (data.listing.page > 1) {
            let url = new URL('users', 'http://localhost');
            url.searchParams.append('p', data.listing.page - 1);
            data.previousPage = url.pathname + (url.search ? url.search : '');
        }

        res.render('users/index', data);
    })
);

router.get(
    '/new',
    asyncifyRequest(async (req, res) => {
        const data = {
            title: 'Create user',
            mainMenuUsers: true,
            layout: 'layouts/main',
            levels
        };

        res.render('users/new', data);
    })
);

router.post(
    '/new',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            username: Joi.string()
                .max(256)
                .trim()
                .lowercase()
                .invalid(config.root.username)
                .required()
                .example('admin')
                .label('Username')
                .description('Username of the user'),
            name: Joi.string().max(256).required().example('admin').label('Name').description('Name of the user'),
            email: Joi.string().email().required().example('admin@example.com').label('Email').description('Email of the user'),
            pgpPubKey: Joi.string()
                .empty('')
                .trim()
                .max(65 * 1024)
                .required()
                .label('PGP Public Key')
                .description('Public key for encryption'),
            level: Joi.string()
                .trim()
                .empty('')
                .valid(...levels.map(l => l.level))
                .default('user')
                .label('User level')
                .description('User permissions level')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = (validationResult && validationResult.value) || {};

        let showErrors = async (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to create a user');
            }

            const data = {
                title: 'Create user',
                mainMenuUsers: true,
                layout: 'layouts/main',

                levels: levels.map(l => {
                    let level = Object.assign({ selected: l.level === values.level }, l);
                    return level;
                }),

                values,
                errors
            };
            res.render('users/new', data);
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

        let existingUser = await users.getByUsername(values.username);
        if (existingUser) {
            return await showErrors({
                username: 'This username already exists'
            });
        }

        values.ip = req.ip;
        values.createdBy = req.user.username;
        try {
            const user = await users.create(values);

            if (user) {
                req.flash('success', 'User created');

                await addToStream(
                    req.user._id || req.user.username,
                    false,
                    'create_user',
                    Object.assign(
                        {
                            owner: {
                                _id: req.user._id,
                                username: req.user.username,
                                name: req.user.name
                            },
                            user: {
                                _id: user,
                                username: values.username,
                                name: values.name
                            },
                            ip: req.ip
                        },
                        values
                    )
                );

                return res.redirect(`/users?created_user=${user}`);
            } else {
                throw new Error('User was not created');
            }
        } catch (err) {
            req.flash('danger', 'Failed to create user');
            return showErrors(false, false);
        }
    })
);

router.get(
    '/user/:id',
    asyncifyRequest(async (req, res) => {
        let paramsSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('User ID')
        });

        const validationResult = paramsSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid user ID provided');
            err.status = 422;
            throw err;
        }

        const values = (validationResult && validationResult.value) || {};

        let userData = await users.get(values.id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        if (req.user._id && userData._id && req.user._id.equals(userData._id)) {
            // use account edit instead
            return res.redirect('/account');
        }

        const data = {
            title: userData.name,
            mainMenuUsers: true,
            layout: 'layouts/main',
            userData,
            fingerprint: userData.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase(),
            label: levels.find(level => userData.level === level.level),
            signFinger: signFinger()
        };

        res.render('users/user', data);
    })
);

router.get(
    '/user/:id/edit',
    asyncifyRequest(async (req, res) => {
        let paramsSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('User ID')
        });

        const validationResult = paramsSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid user ID provided');
            err.status = 422;
            throw err;
        }

        const values = (validationResult && validationResult.value) || {};

        let userData = await users.get(values.id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        if (req.user._id && userData._id && req.user._id.equals(userData._id)) {
            // use account edit instead
            return res.redirect('/account/edit');
        }

        const data = {
            title: 'Edit user',
            mainMenuUsers: true,
            layout: 'layouts/main',
            levels: levels.map(l => {
                let level = Object.assign({ selected: l.level === userData.level }, l);
                return level;
            }),
            userData,
            values: userData,

            fingerprint: userData.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase()
        };

        res.render('users/edit', data);
    })
);

router.post(
    '/edit',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('User ID'),
            name: Joi.string().max(256).required().example('admin').label('Name').description('Name of the user'),
            email: Joi.string().email().required().example('admin@example.com').label('Email').description('Email of the user'),

            level: Joi.string()
                .trim()
                .empty('')
                .valid(...levels.map(l => l.level))
                .default('user')
                .label('User level')
                .description('User permissions level'),

            resetPassword: Joi.boolean().truthy('Y', 'true', '1', 'on').default(false).label('Reset password').description('Generate new password for the user')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = (validationResult && validationResult.value) || {};

        let userData = await users.get(values.id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        if (req.user._id && userData._id && req.user._id.equals(userData._id)) {
            // use account edit instead
            return res.redirect('/account/edit');
        }

        let showErrors = async (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to update user');
            }

            const data = {
                title: 'Edit user',
                mainMenuUsers: true,
                layout: 'layouts/main',

                levels: levels.map(l => {
                    let level = Object.assign({ selected: l.level === values.level }, l);
                    return level;
                }),

                userData,
                fingerprint: userData.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase(),

                values,
                errors
            };
            res.render('users/edit', data);
        };

        if (validationResult.error) {
            let errors = validationErrors(validationResult);
            return await showErrors(errors);
        }

        let updates = {
            name: values.name,
            email: values.email,
            level: values.level
        };

        if (values.resetPassword) {
            updates = Object.assign(updates, await users.resetCredentials(userData));
        }

        try {
            const updated = await users.update(values.id, updates);

            if (updated) {
                if (updates.credentials) {
                    req.flash('success', 'Password for the user was regenerated');
                } else {
                    req.flash('success', 'User updated');
                }

                await addToStream(
                    req.user._id || req.user.username,
                    false,
                    'edit_user',
                    Object.assign(
                        {
                            owner: {
                                _id: req.user._id,
                                username: req.user.username,
                                name: req.user.name
                            },
                            user: {
                                _id: userData._id,
                                username: userData.username,
                                name: userData.name
                            },
                            ip: req.ip
                        },
                        values
                    )
                );

                return res.redirect(`/users/user/${values.id}`);
            } else {
                return res.redirect(`/users/user/${values.id}`);
            }
        } catch (err) {
            req.flash('danger', 'Failed to update user');
            return showErrors(false, false);
        }
    })
);

router.post(
    '/delete',
    asyncifyRequest(async (req, res) => {
        let loginSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('User ID')
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid user ID provided');
            err.status = 422;
            throw err;
        }

        const values = (validationResult && validationResult.value) || {};

        let userData = await users.get(values.id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        if (req.user._id && userData._id && req.user._id.equals(userData._id)) {
            // use account edit instead
            return res.redirect('/account/edit');
        }

        const deleted = await users.delete(values.id);
        if (deleted) {
            req.flash('success', 'User was deleted');

            await addToStream(
                req.user._id || req.user.username,
                false,
                'delete_user',
                Object.assign(
                    {
                        owner: {
                            _id: req.user._id,
                            username: req.user.username,
                            name: req.user.name
                        },
                        user: {
                            _id: userData._id,
                            username: userData.username,
                            name: userData.name
                        },
                        ip: req.ip
                    },
                    values
                )
            );
        }

        return res.redirect(`/users`);
    })
);

router.get(
    '/fetch/:id/credentials.gpg',
    asyncifyRequest(async (req, res) => {
        let auditListingSchema = Joi.object({
            id: Joi.string().empty('').hex().length(24).required().label('User ID')
        });

        const validationResult = auditListingSchema.validate(req.params, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        if (validationResult.error) {
            let err = new Error('Invalid user ID provided');
            err.status = 422;
            throw err;
        }

        const values = (validationResult && validationResult.value) || {};
        const credentials = await users.getCredentials(values.id);
        if (!credentials || !credentials.credentials) {
            let err = new Error('Requested credentials were not found');
            err.status = 404;
            throw err;
        }

        await addToStream(
            req.user._id || req.user.username,
            false,
            'fetch_user_creds',
            Object.assign(
                {
                    owner: {
                        _id: req.user._id,
                        username: req.user.username,
                        name: req.user.name
                    },
                    user: {
                        _id: credentials._id,
                        username: credentials.username,
                        name: credentials.name
                    },
                    ip: req.ip
                },
                values
            )
        );

        res.set('Content-Type', 'text/plain');
        res.setHeader('Content-disposition', 'attachment; filename=credentials.gpg');
        res.send(Buffer.from(credentials.credentials));
    })
);

module.exports = router;
