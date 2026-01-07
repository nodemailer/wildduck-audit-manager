'use strict';

const express = require('express');
const router = new express.Router();
const Joi = require('@hapi/joi');
const { asyncifyRequest, validationErrors } = require('../lib/tools');
const { requireLogin, requireAdmin, requireRoot, login, logout } = require('../lib/passport');

router.use('/audits', requireLogin, require('./audits/index'));
router.use('/account', requireLogin, require('./account/index'));
router.use('/users', requireAdmin, require('./users/index'));
router.use('/stream', requireRoot, require('./stream/index'));

router.get(
    '/',
    asyncifyRequest(async (req, res) => {
        res.render('root/index', {
            msg: 'Hello world root',
            layout: 'layouts/main'
        });
    })
);

router.get(
    '/login',
    asyncifyRequest(async (req, res) => {
        if (req.user) {
            // already logged in
            return res.redirect('/');
        }
        res.render('root/login', {
            mainMenuLogin: true,
            title: 'Log in',
            layout: 'layouts/main'
        });
    })
);

router.get('/logout', (req, res, next) => {
    req.flash(); // clear pending messages
    logout(req, res, next);
});

router.post('/login', (req, res, next) => {
    let loginSchema = Joi.object({
        username: Joi.string().max(256).required().example('admin').label('Username').description('Username'),
        password: Joi.string().max(256).required().example('secret').label('Password').description('Password'),
        remember: Joi.boolean().truthy('Y', 'true', '1', 'on').default(false).label('Remember me').description('Remember login in this browser')
    });

    const validationResult = loginSchema.validate(req.body, {
        stripUnknown: true,
        abortEarly: false,
        convert: true
    });

    const values = validationResult && validationResult.value;

    let showErrors = (errors, disableDefault) => {
        if (!disableDefault) {
            req.flash('danger', 'Authentication failed');
        }
        res.render('root/login', {
            mainMenuLogin: true,
            title: 'Log in',
            layout: 'layouts/main',
            values,
            errors
        });
    };

    if (validationResult.error) {
        return showErrors(validationErrors(validationResult));
    }

    login(req, res, next);
});

module.exports = router;
