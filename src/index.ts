import { createReadStream, createWriteStream, mkdirSync, readFileSync, writeFile, WriteStream } from 'fs';
import { createServer, IncomingHttpHeaders, IncomingMessage } from 'http';
import { parse } from 'querystring';
import { Speedport } from './speedport';

interface Config {
    speedport: {
        host: string;
        password: string;
    };
    cacheEnabled: boolean;
    proxy: {
        host: string;
        port: number;
        url: string;
    };
}

const config = <Config> JSON.parse(readFileSync('./config').toString('utf8'));

try {
    mkdirSync('cache');
} catch (e) {
    console.error(e.stack || e);
    if (config.cacheEnabled) {
        process.exit(1);
    }
}

const sp = new Speedport(config.speedport.host, config.speedport.password);

const BADURLS = [
    '/',
    '/html',
    '/html/',
    '/html/login',
    '/html/login/',
    '/html/login/index.html',
];

const ALLOWED_HEADERS = [
    'x-requested-with',
    'origin',
    'referer',
];

const LOGOUT_SUCCESS = JSON.stringify(
    [
        {
            varid: 'status',
            vartype: 'status',
            varvalue: 'ok',
        },
    ],
);

interface CacheData {
    headers: IncomingHttpHeaders;
    statusCode: number;
}

const cache: { [key: string]: CacheData; } = (() => {
    try {
        return require('./cache/index');
    } catch (e) {
        return {};
    }
})();

function makeCacheURL(url: string) {
    return url.replace(/[^A-Za-z0-9.]/g, '_');
}

const listener = createServer((req, res) => {
    const data: Buffer[] = [];

    req.on('data', (chunk: Buffer) => {
        data.push(chunk);
    });

    req.on('end', () => {
        const urlPath = req.url!.replace(/\?.*$/, '');

        if (urlPath === '/data/heartbeat.json') {
            res.writeHead(200, {
                'Content-Type': 'application/javascript',
            });
            res.write(sp.lastHeartbeat);
            res.end();
            return;
        }

        const strData = data.length > 0 ? Buffer.concat(data).toString('utf8') : undefined;

        if (urlPath === '/data/Login.json' && strData !== undefined) { // Interject!
            const post = parse(strData);
            let reply = '';
            if (post.challengev === 'null') {
                reply = sp.loginStageOneReply!;
            } else if (post.password) {
                reply = sp.loginStageTwoReply!;
            } else if (post.logout === 'byby') {
                reply = LOGOUT_SUCCESS;
            }
            if (reply) {
                res.writeHead(200, {
                    'Content-Type': 'application/javascript',
                });
                res.write(reply);
            } else {
                res.writeHead(404);
            }
            res.end();
            return;
        }

        if (BADURLS.indexOf(urlPath) >= 0) {
            if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
                res.writeHead(403);
                res.end();
                return;
            }
            res.writeHead(302, {
                Location: `${config.proxy.url}/html/content/overview/index.html`,
            });
            res.end();
            return;
        }

        let isStatic = true;
        const fileExtension = (urlPath.indexOf('.') > 0) ?
            urlPath.substr(urlPath.lastIndexOf('.') + 1).toLowerCase() :
            'bin';
        if (fileExtension === 'htm' || fileExtension === 'html' || fileExtension === 'json') {
            isStatic = false;
        }
        if (req.method !== 'GET') {
            isStatic = false;
        }

        if (isStatic && cache[urlPath] && config.cacheEnabled) {
            const cData = cache[urlPath];
            res.writeHead(cData.statusCode, cData.headers);
            createReadStream(`./cache/data_${makeCacheURL(urlPath)}`).pipe(res);
            return;
        }

        const headers: IncomingHttpHeaders = {};
        ALLOWED_HEADERS.forEach(headerName => {
            if (req.headers[headerName]) {
                headers[headerName] = req.headers[headerName];
            }
        });

        // tslint:disable-next-line:max-line-length
        headers['user-agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36';

        if (headers.referer) {
            headers.referer = (<string> headers.referer!).replace(config.proxy.url, 'http://speedport.ip');
        }
        headers.host = 'speedport.ip';
        if (headers.origin) {
            headers.origin = (<string> headers.origin!).replace(config.proxy.url, 'http://speedport.ip');
        }

        sp.request({
            http: {
                headers,
                method: req.method,
                path: req.url,
            },
            loginTries: isStatic ? 0 : undefined,
            noCookies: isStatic,
        }, strData, (err?: Error, spres?: IncomingMessage) => {
            if (err) {
                console.warn(err);
                // Stuff
                res.writeHead(500);
                res.write('Internal SPAuthProxy error');
                res.end();
                return;
            }
            delete spres!.connection;

            spres!.headers['x-caching'] = isStatic ? 'LOOKUP' : 'PASS';
            res.writeHead(spres!.statusCode!, spres!.headers);

            let cData: CacheData;
            let cStream: WriteStream;
            if (isStatic && config.cacheEnabled) {
                spres!.headers['x-caching'] = 'HIT';
                delete spres!.headers.date;
                delete spres!.headers['content-length'];
                delete spres!.headers.connection;
                cData = {
                    headers: spres!.headers,
                    statusCode: spres!.statusCode!,
                };
                cStream = createWriteStream(`./cache/data_${makeCacheURL(urlPath)}`);
            }

            spres!.on('data', (spData: string) => {
                res.write(spData);
                if (cStream) {
                    cStream.write(spData);
                }
            });

            spres!.on('end', () => {
                res.end();
                if (cData && config.cacheEnabled) {
                    cache[urlPath] = cData;
                    writeFile('./cache/index.json', JSON.stringify(cache), cErr => {
                        if (cErr) {
                            console.warn(`Error writing cache: ${cErr}`);
                        }
                    });
                }
            });
        });
    });
});
listener.listen(config.proxy.port, config.proxy.host);
