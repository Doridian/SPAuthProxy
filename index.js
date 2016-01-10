var config = require('./config');

var Speedport = require('./speedport');
var http = require('http');

var sp = new Speedport(config.speedport.host, config.speedport.password);

var REQUESTID = 0;

var BADURLS = [
	'/',
	'/html',
	'/html/',
	'/html/login',
	'/html/login/',
	'/html/login/index.html',
	'/data/Login.json'
];

var ALLOWED_HEADERS = [
	'x-requested-with',
	'origin',
	'referer'
];

var listener = http.createServer(function (req, res) {
	req.setEncoding('utf8');
	//res.setEncoding('utf8');

	var hasData = false;
	var data = "";

	req.on('data', function (chunk) {
		data += chunk;
		hasData = true;
	});

	req.on('end', function () {
		var headers = req.headers;

		var urlPath = req.url.replace(/\?.*$/, '');

		if(urlPath === '/data/heartbeat.json') {
			res.writeHead(200);
			res.write(JSON.stringify([
			    {
			        vartype:"status",
			        varid:"loginstate",
			        varvalue:"1"
			    }
			]));
			res.end();
			return;
		}

		if(BADURLS.indexOf(urlPath) >= 0) {
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

		var noLoginNeeded = true;
		var fileExtension = (urlPath.indexOf('.') > 0) ? urlPath.substr(urlPath.lastIndexOf('.') + 1).toLowerCase() : 'bin';
		if(fileExtension === 'htm' || fileExtension === 'html' || fileExtension === 'json') {
			noLoginNeeded = false;
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
			path: req.url,
			method: req.method,
			headers: headers,
			noLogin: noLoginNeeded
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
			res.writeHead(spres.statusCode, spres.headers);
			spres.on('data', function (data) {
				res.write(data);
			});
			spres.on('end', function () {
				res.end();
			});
			spres.on('error', function (err) {
				console.error(err);
			});
		});
	});
});
listener.listen(config.proxy.port, config.proxy.host);
