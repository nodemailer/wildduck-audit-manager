'use strict';

const express = require('express');
const router = new express.Router();
const { asyncifyRequest, validationErrors, checkPubKey } = require('../../lib/tools');
const users = require('../../lib/users');
const { PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST } = require('../../lib/consts');
const Joi = require('@hapi/joi');
const pbkdf2 = require('@phc/pbkdf2');
const config = require('wild-config');

router.get(
    '/',
    asyncifyRequest(async (req, res) => {
        if (req.user.username === config.root.username) {
            return res.redirect('/users');
        }

        let userData = await users.get(req.user._id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        const data = {
            title: userData.name,
            mainMenuAccount: true,
            layout: 'layouts/main',
            userData,
            fingerprint: userData.keyData.fingerprint.split(':').slice(-8).join('').toUpperCase()
        };

        res.render('account/index', data);
    })
);

router.get(
    '/edit',
    asyncifyRequest(async (req, res) => {
        if (req.user.username === config.root.username) {
            return res.redirect('/users');
        }

        let userData = await users.get(req.user._id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        userData.password = '';

        const data = {
            title: userData.name,
            mainMenuAccount: true,
            layout: 'layouts/main',
            userData,
            values: userData
        };

        res.render('account/edit', data);
    })
);

router.post(
    '/edit',
    asyncifyRequest(async (req, res) => {
        if (req.user.username === config.root.username) {
            return res.redirect('/users');
        }

        let loginSchema = Joi.object({
            name: Joi.string().max(256).required().example('admin').label('Name').description('Name of the user'),
            email: Joi.string().email().required().example('admin@example.com').label('Email').description('Email of the user'),
            pgpPubKey: Joi.string()
                .empty('')
                .trim()
                .max(65 * 1024)
                .required()
                .label('PGP Public Key')
                .description('Public key for encryption'),

            passwordCurrent: Joi.string()
                .empty('')
                .max(256)
                .example('secret')
                .label('Currrent password')
                .description('Current password')
                .when('password', { not: '', then: Joi.string().required() }),
            password: Joi.string().allow('').max(256).min(12).example('secret').label('New password').description('New password'),
            password2: Joi.string().max(256).example('secret').label('Repeat password').description('Repeat password').valid(Joi.ref('password'))
        });

        const validationResult = loginSchema.validate(req.body, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = (validationResult && validationResult.value) || {};

        let userData = await users.get(req.user._id);
        if (!userData) {
            let err = new Error('User Not Found');
            err.status = 404;
            throw err;
        }

        let showErrors = async (errors, disableDefault) => {
            if (!disableDefault) {
                req.flash('danger', 'Failed to update user');
            }

            userData.password = '';
            const data = {
                title: userData.name,
                mainMenuAccount: true,
                layout: 'layouts/main',

                userData,

                values,
                errors
            };
            res.render('account/edit', data);
        };

        if (validationResult.error) {
            let errors = validationErrors(validationResult);
            return await showErrors(errors);
        }

        let updates = {
            name: values.name,
            email: values.email
        };

        try {
            updates.keyData = await checkPubKey(values.pgpPubKey);
        } catch (err) {
            return await showErrors({
                pgpPubKey: 'PGP key validation failed. ' + err.message
            });
        }

        if (values.password) {
            // verify current password
            const verified = await pbkdf2.verify(userData.password, values.passwordCurrent);
            if (!verified) {
                return await showErrors({
                    passwordCurrent: 'Invalid password'
                });
            }

            // update password as well
            updates.password = await pbkdf2.hash(values.password, {
                iterations: PDKDF2_ITERATIONS,
                saltSize: PDKDF2_SALT_SIZE,
                digest: PDKDF2_DIGEST
            });
            updates.passwordUpdated = new Date();
        }

        try {
            const updated = await users.update(req.user._id, updates);
            if (updated) {
                req.flash('success', 'Account data updated');
            }
            return res.redirect(`/account`);
        } catch (err) {
            req.flash('danger', 'Failed to update account data');
            return showErrors(false, false);
        }
    })
);

module.exports = router;
