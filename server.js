'use strict';

try {
    process.chdir(__dirname);
} catch (err) {
    // ignore
}

// cache before wild-config
const argv = process.argv.slice(2);

const logger = require('./lib/logger');
const pathlib = require('path');
const { Worker, SHARE_ENV } = require('worker_threads');

const config = require('wild-config');
process.title = config.process.title;

if (
    process.env.NODE_ENV === 'production' &&
    config.root.enabled &&
    config.root.passwordHash === '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
) {
    console.error('--------');
    console.error('Using default root password is not allowed in production mode.');
    console.error('Update root.passwordHash option in the config file or disable root login.');
    console.error('--------');
    process.exit(1);
}

let closing = false;

let workers = new Map();

let spawnWorker = type => {
    if (closing) {
        return;
    }

    if (!workers.has(type)) {
        workers.set(type, new Set());
    }

    let worker = new Worker(pathlib.join(__dirname, 'workers', `${type}.js`), {
        argv,
        env: SHARE_ENV
    });

    workers.get(type).add(worker);

    worker.on('exit', exitCode => {
        workers.get(type).delete(worker);

        if (closing) {
            return;
        }

        // spawning a new worker trigger reassign
        logger.error({ msg: 'Worker exited', exitCode });
        setTimeout(() => spawnWorker(type), 1000);
    });
};

if (config.web.enabled) {
    // single worker for HTTP
    spawnWorker('web');
}

const closeProcess = code => {
    if (closing) {
        return;
    }
    closing = true;
    setTimeout(() => {
        process.exit(code);
    }, 10);
};

process.on('uncaughtException', () => closeProcess(1));
process.on('unhandledRejection', () => closeProcess(2));
process.on('SIGTERM', () => closeProcess(0));
process.on('SIGINT', () => closeProcess(0));
