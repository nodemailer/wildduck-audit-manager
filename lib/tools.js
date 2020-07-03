'use strict';

const openpgp = require('openpgp');
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const punycode = require('punycode');
const config = require('wild-config');
const pkg = require('../package.json');

openpgp.config.commentstring = config.app.pgp.comment || 'https://wildduck.email';
openpgp.config.versionstring = config.app.pgp.version || `WildDuck Audit v${pkg.version}`;

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

const formatFingerprint = fingerprint => {
    let out = [];
    for (let nr of fingerprint) {
        out.push((nr < 0x10 ? '0' : '') + nr.toString(16).toLowerCase());
    }
    return out.join(':');
};

function normalizeDomain(domain) {
    domain = (domain || '').toLowerCase().trim();
    try {
        if (/^xn--/.test(domain)) {
            domain = punycode.toUnicode(domain).normalize('NFC').toLowerCase().trim();
        }
    } catch (E) {
        // ignore
    }

    return domain;
}

function normalizeAddress(address) {
    let user = address.substr(0, address.lastIndexOf('@')).normalize('NFC').toLowerCase().trim();
    let domain = normalizeDomain(address.substr(address.lastIndexOf('@') + 1));

    return `${user}@${domain}`;
}

async function getKeyInfo(pubKey) {
    if (!pubKey) {
        return false;
    }

    // try to encrypt something with that key
    let armored;
    try {
        armored = (await openpgp.key.readArmored(pubKey)).keys;
    } catch (E) {
        return false;
    }

    if (!armored || !armored[0]) {
        return false;
    }

    let fingerprint = armored[0].primaryKey.fingerprint;
    let name, address;
    if (armored && armored[0] && armored[0].users && armored[0].users[0] && armored[0].users[0].userId) {
        let user = addressparser(armored[0].users[0].userId.userid);
        if (user && user[0] && user[0].address) {
            address = normalizeAddress(user[0].address);
            try {
                name = libmime.decodeWords(user[0].name || '').trim();
            } catch (E) {
                // failed to parse value
                name = user[0].name || '';
            }
        }
    }

    if (fingerprint && typeof fingerprint === 'object') {
        // convert to hex string
        fingerprint = Array.from(fingerprint)
            .map(byte => (byte < 0x10 ? '0' : '') + byte.toString(16))
            .join('');
    }

    return {
        name,
        address,
        fingerprint
    };
}

async function checkPubKey(pubKey) {
    if (!pubKey) {
        return false;
    }

    // try to encrypt something with that key
    let armored = (await openpgp.key.readArmored(pubKey)).keys;

    if (!armored || !armored[0]) {
        throw new Error('Did not find key information');
    }

    let fingerprint = armored[0].primaryKey.fingerprint;
    let name, address;
    if (armored && armored[0] && armored[0].users && armored[0].users[0] && armored[0].users[0].userId) {
        let user = addressparser(armored[0].users[0].userId.userid);
        if (user && user[0] && user[0].address) {
            address = normalizeAddress(user[0].address);
            try {
                name = libmime.decodeWords(user[0].name || '').trim();
            } catch (E) {
                // failed to parse value
                name = user[0].name || '';
            }
        }
    }

    let ciphertext = await openpgp.encrypt({
        message: openpgp.message.fromText('Hello, World!'),
        publicKeys: armored
    });

    if (/^-----BEGIN PGP MESSAGE/.test(ciphertext.data)) {
        // everything checks out
        return {
            name,
            address,
            fingerprint: formatFingerprint(fingerprint)
        };
    }

    throw new Error('Unexpected message');
}

const encrypt = async (pubKey, data) => {
    if (!pubKey) {
        return false;
    }

    if (typeof data === 'string') {
        data = Buffer.from(data);
    }

    // try to encrypt something with that key
    let armored = (await openpgp.key.readArmored(pubKey)).keys;

    if (!armored || !armored[0]) {
        throw new Error('Did not find key information');
    }

    let ciphertext = await openpgp.encrypt({
        message: openpgp.message.fromBinary(data),
        publicKeys: armored,
        compression: openpgp.enums.compression.zip
    });

    return ciphertext.data;
};

module.exports = { asyncifyRequest, asyncifyJson, validationErrors, getKeyInfo, checkPubKey, encrypt };
