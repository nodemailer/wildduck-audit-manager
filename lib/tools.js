'use strict';

const asyncifyRequest = middleware => async (req, res, next) => {
    try {
        await middleware(req, res, next);
    } catch (err) {
        req.log.error({ msg: 'Failed to process request', req, res, err });
        next(err);
    }
};

const asyncifyJson = middleware => async (req, res, next) => {
    try {
        await middleware(req, res, next);
    } catch (err) {
        let data = {
            error: err.message
        };

        if (err.responseCode) {
            res.status(err.responseCode);
        }

        if (err.code) {
            data.code = err.code;
        }

        req.log.error({ msg: 'Failed to process request', req, res, err });

        res.charSet('utf-8');
        res.json(data);
        return next();
    }
};

const validationErrors = validationResult => {
    const errors = {};
    if (validationResult.error && validationResult.error.details) {
        validationResult.error.details.forEach(detail => {
            if (!errors[detail.path]) {
                errors[detail.path] = detail.message;
            }
        });
    }
    return errors;
};

module.exports = { asyncifyRequest, asyncifyJson, validationErrors };
