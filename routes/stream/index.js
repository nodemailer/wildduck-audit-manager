'use strict';

const express = require('express');
const router = new express.Router();
const { asyncifyRequest } = require('../../lib/tools');
const Joi = require('@hapi/joi');
const URL = require('url').URL;
const { list } = require('../../lib/stream');

router.get(
    '/',
    asyncifyRequest(async (req, res) => {
        let requestSchema = Joi.object({
            p: Joi.number()
                .empty('')
                .min(1)
                .max(64 * 1024)
                .default(1)
                .example(1)
                .label('Page Number')
        });

        const validationResult = requestSchema.validate(req.query, {
            stripUnknown: true,
            abortEarly: false,
            convert: true
        });

        const values = validationResult && validationResult.value;
        const page = values && !validationResult.error ? values.p : 0;

        const data = {
            title: 'Stream',
            mainMenuStream: true,
            layout: 'layouts/main'
        };

        const query = {};

        data.listing = await list(query, page);

        if (data.listing.page < data.listing.pages) {
            let url = new URL('stream', 'http://localhost');
            url.searchParams.append('p', data.listing.page + 1);
            data.nextPage = url.pathname + (url.search ? url.search : '');
        }

        if (data.listing.page > 1) {
            let url = new URL('stream', 'http://localhost');
            url.searchParams.append('p', data.listing.page - 1);
            data.previousPage = url.pathname + (url.search ? url.search : '');
        }

        res.render('stream/index', data);
    })
);

module.exports = router;
