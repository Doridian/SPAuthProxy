var config = require('./config');
var fs = require('fs');

try { fs.mkdirSync('cache') } catch(e) { }

var Speedport = require('./speedport');
var http = require('http');

var sp = new Speedport(config.speedport.host, config.speedport.password);

var BADURLS = [
	'/',
	'/html',
	'/html/',
	'/html/login',
	'/html/login/',
	'/html/login/index.html'
];

var ALLOWED_HEADERS = [
	'x-requested-with',
	'origin',
	'referer'
];

var cache = require('./cache/index');

function makeCacheURL (url) {
	return url.replace(/[^A-Za-z0-9.]/g, '_');
}

var listener = http.createServer(function (req, res) {
	req.setEncoding('utf8');

	var hasData = false;
	var data = "";

	req.on('data', function (chunk) {
		data += chunk;
		hasData = true;
	});

	req.on('end', function () {
		var headers = req.headers;

		var urlPath = req.url.replace(/\?.*$/, '');

		if (urlPath === '/data/heartbeat.json') {
			res.writeHead(200);
			res.write(sp.getHeartbeat());
			res.end();
			return;
		}

		if (BADURLS.indexOf(urlPath) >= 0 || (urlPath === '/data/Login.json' && req.method !== 'GET')) {
			if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
				res.writeHead(403);
				res.end();
				return;
			}
			res.writeHead(302, {
				Location: config.proxy.url + '/html/content/overview/index.html'
			});
			res.end();
			return;
		}

		var isStatic = true;
		var fileExtension = (urlPath.indexOf('.') > 0) ? urlPath.substr(urlPath.lastIndexOf('.') + 1).toLowerCase() : 'bin';
		if (fileExtension === 'htm' || fileExtension === 'html' || fileExtension === 'json') {
			isStatic = false;
		}
		if (req.method !== 'GET') {
			isStatic = false;
		}

		if (isStatic && cache[urlPath]) {
			var cData = cache[urlPath];
			res.writeHead(cData.statusCode, cData.headers);
			fs.createReadStream('./cache/data_' + makeCacheURL(urlPath)).pipe(res);
			return;
		}

		var headers = {};
		ALLOWED_HEADERS.forEach(function (headerName) {
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
		}, (hasData ? data : null), function (err, spres) {
			if (err) {
				console.log(err);
				// Stuff
				res.writeHead(500);
				res.write('Internal SPAuthProxy error');
				res.end();
				return;
			}
			delete spres.connection;

			spres.headers['x-caching'] = isStatic ? 'LOOKUP' : 'PASS';
			res.writeHead(spres.statusCode, spres.headers);

			var cData = null;
			var cStream = null;
			if (isStatic) {
				spres.headers['x-caching'] = 'HIT';
				delete spres.headers.date;
				delete spres.headers['content-length'];
				delete spres.headers.connection;
				cData = {
					headers: spres.headers,
					statusCode: spres.statusCode
				};
				cStream = fs.createWriteStream('./cache/data_' + makeCacheURL(urlPath));
			}

			spres.on('data', function (data) {
				res.write(data);
				if (cStream) {
					cStream.write(data);
				}
			});

			spres.on('end', function () {
				res.end();
				if (cData) {
					cache[urlPath] = cData;
					fs.writeFile('./cache/index.json', JSON.stringify(cache), function (err) {
						if (err)
							console.warn('Error writing cache: ' + err);
					});
				}
			});
		});
	});
});
listener.listen(config.proxy.port, config.proxy.host);
