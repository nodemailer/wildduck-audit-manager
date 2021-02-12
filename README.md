# WildDuck Audit Manager

WildDuck Audit system allows to debug email accounts in a [WildDuck email server](https://wildduck.email/). When auditing is enabled for an email account then all messages that match the given timeframe are copied to the auditing system for inspection. Once the audit reaches its expiration date all data related to the audit is deleted from the system.

## Features

-   Can create additional admin users to manage audits
-   Can manage audits for email accounts
-   Can grant access to audit data based on PGP key
-   Can not access audit data (see [WildDuck Audit Client](https://github.com/nodemailer/wildduck-audit-client) for data access)
-   Does not send any information over email. Instead access information is downloadable and encrypted with recipient's PGP key. Encrypted access data can be downloaded once and downloads are logged.
-   Logs admin user activities

## Usage

```
$ npm install --production
$ npm start
```

### Configuration

Configuration resides in [config/default.toml](config/default.toml). For better manageability you can create a separate config file for server specific options that is then merged with default config options.

**Example systemd unit file**

This service definition merges configuration options from /path/to/audit-manager.toml with default.toml

```
[Service]
Environment="NODE_CONFIG_PATH=/path/to/audit-manager.toml"
Environment="NODE_ENV=production"
WorkingDirectory=/path/to/wildduck-audit-manager
ExecStart=/usr/bin/npm start
```

### Root user

You can use the root user to authenticate and create regular admin users. It is advised to disable the root user once you have created regular admin users.

Root account can be edited in the config file. See the `[root]` section.

By default there is a root user set up with the following credentials:

-   username: **root**
-   password: **test**

> **NB** If `NODE_ENV` environment variable is "production" then the application refuses to start unless the root password has been changed.

### Considerations

-   Disable the root user once regular users are set up
-   Disable external access to WildDuck Audit Manager, it should be available from internal IP addresses only

## License

WildDuck Audit Manager is licensed under the [European Union Public License 1.2](LICENSE) or later.
