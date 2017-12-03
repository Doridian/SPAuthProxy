'use strict';

const config = require('./config');
const fs = require('fs');
const http = require('http');
const qs = require('querystring');

try { fs.mkdirSync('cache') } catch(e) { }

const Speedport = require('./speedport');

const sp = new Speedport(config.speedport.host, config.speedport.password);

const BADURLS = [
	'/',
	'/html',
	'/html/',
	'/html/login',
	'/html/login/',
	'/html/login/index.html'
];

const ALLOWED_HEADERS = [
	'x-requested-with',
	'origin',
	'referer'
];

const LOGOUT_SUCCESS = '[{"vartype":"status","varid":"status","varvalue":"ok"}]';

const cache = require('./cache/index');

function makeCacheURL (url) {
	return url.replace(/[^A-Za-z0-9.]/g, '_');
}

const listener = http.createServer((req, res) => {
	req.setEncoding('utf8');

	const hasData = false;
	let data = '';

	req.on('data', (chunk) => {
		data += chunk;
		hasData = true;
	});

	req.on('end', () => {
		const headers = req.headers;

		const urlPath = req.url.replace(/\?.*$/, '');

		if (urlPath === '/data/heartbeat.json') {
			res.writeHead(200, {
				'Content-Type': 'application/javascript'
			});
			res.write(sp.lastHeartbeat);
			res.end();
			return;
		}

		if (urlPath === '/data/Login.json' && hasData) { // Interject!
			const post = qs.parse(data);
			const reply = null;
			if (post.challengev === 'null') {
				reply = sp.loginStageOneReply;
			} else if(post.password) {
				reply = sp.loginStageTwoReply;
			} else if(post.logout == 'byby') {
				reply = LOGOUT_SUCCESS;
			}
			if (reply) {
				res.writeHead(200, {
					'Content-Type': 'application/javascript'
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
				Location: `${config.proxy.url}/html/content/overview/index.html`
			});
			res.end();
			return;
		}

		let isStatic = true;
		const fileExtension = (urlPath.indexOf('.') > 0) ? urlPath.substr(urlPath.lastIndexOf('.') + 1).toLowerCase() : 'bin';
		if (fileExtension === 'htm' || fileExtension === 'html' || fileExtension === 'json') {
			isStatic = false;
		}
		if (req.method !== 'GET') {
			isStatic = false;
		}

		if (isStatic && cache[urlPath] && config.cacheEnabled) {
			const cData = cache[urlPath];
			res.writeHead(cData.statusCode, cData.headers);
			fs.createReadStream(`./cache/data_${makeCacheURL(urlPath)}`).pipe(res);
			return;
		}

		const headers = {};
		ALLOWED_HEADERS.forEach((headerName) => {
			if (req.headers[headerName]) {
				headers[headerName] = req.headers[headerName];
			}
		});
		
		headers['user-agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36';
		if (headers.referer) {
			headers.referer = headers.referer.replace(config.proxy.url, 'http://speedport.ip');
		}
		headers.host = 'speedport.ip';
		if (headers.origin) {
			headers.origin = headers.origin.replace(config.proxy.url, 'http://speedport.ip');
		}

		sp.request({
			http: {
				path: req.url,
				method: req.method,
				headers: headers
			},
			loginTries: isStatic ? 0 : undefined,
			noCookies: isStatic
		}, (hasData ? data : null), (err, spres) => {
			if (err) {
				console.warn(err);
				// Stuff
				res.writeHead(500);
				res.write('Internal SPAuthProxy error');
				res.end();
				return;
			}
			delete spres.connection;

			spres.headers['x-caching'] = isStatic ? 'LOOKUP' : 'PASS';
			res.writeHead(spres.statusCode, spres.headers);

			let cData = null;
			let cStream = null;
			if (isStatic && config.cacheEnabled) {
				spres.headers['x-caching'] = 'HIT';
				delete spres.headers.date;
				delete spres.headers['content-length'];
				delete spres.headers.connection;
				cData = {
					headers: spres.headers,
					statusCode: spres.statusCode
				};
				cStream = fs.createWriteStream(`./cache/data_${makeCacheURL(urlPath)}`);
			}

			spres.on('data', (data) => {
				res.write(data);
				if (cStream) {
					cStream.write(data);
				}
			});

			spres.on('end', () => {
				res.end();
				if (cData && config.cacheEnabled) {
					cache[urlPath] = cData;
					fs.writeFile('./cache/index.json', JSON.stringify(cache), (err) => {
						if (err)
							console.warn(`Error writing cache: ${err}`);
					});
				}
			});
		});
	});
});
listener.listen(config.proxy.port, config.proxy.host);
