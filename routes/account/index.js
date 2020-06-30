'use strict';

const express = require('express');
const router = new express.Router();
const { asyncifyRequest } = require('../../lib/tools');

router.get(
    '/',
    asyncifyRequest(async (req, res) => {
        res.render('root/index', {
            title: 'Account page',
            msg: 'Hello world account',
            layout: 'layouts/main'
        });
    })
);

module.exports = router;
