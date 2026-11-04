var net = require('net');

// Endpoint reachability check, applied to every aws-sdk request.
//
// A service endpoint that never answers is the most expensive thing a scan can
// hit: the SDK sets no connect timeout, so every attempt waits out the OS's TCP
// SYN retries (about two minutes), and the collectors' maxRetries of 8 turns a
// single request into about twenty. Retired services whose hostnames still
// resolve (CodeStar) and regions in an outage did exactly that.
//
// So before a request is signed, the endpoint it is going to is probed with a
// plain TCP connection, and the handshake gets a short timeout. A hostname
// that no longer exists counts as unreachable too. Each host is probed once per
// process - concurrent requests wait on the same probe - and a request to a
// host that did not answer fails straight away with EndpointUnreachable, which
// is not retried. Collectors record it like any other API error.
//
// With an HTTPS proxy configured the SDK never connects to endpoints directly,
// so a direct probe would say nothing about them; the check is then off.

var PROBE_TIMEOUT_MS = 10000;

var installed = false;

// host -> {state: 'pending' | 'reachable' | 'unreachable', reason, waiting, skipped}
var hosts = {};

var proxyConfigured = function() {
    return !!(process.env.https_proxy || process.env.HTTPS_PROXY ||
        process.env.all_proxy || process.env.ALL_PROXY);
};

var unreachableError = function(host, reason) {
    var err = new Error(host + ' is unreachable (' + reason + '); request not sent');
    err.code = 'EndpointUnreachable';
    err.retryable = false;
    return err;
};

// Probes host:443 once. Calls back with null if it accepted a connection, or
// with the reason it did not.
var probe = function(host, callback) {
    var entry = hosts[host];
    if (entry) {
        if (entry.state === 'pending') return entry.waiting.push(callback);
        return callback(entry.reason);
    }

    entry = hosts[host] = {state: 'pending', reason: null, waiting: [callback], skipped: 0};

    var settled = false;
    var connectTimer = null;
    var socket = net.connect({host: host, port: 443});
    var finish = function(reason) {
        if (settled) return;
        settled = true;
        clearTimeout(connectTimer);
        socket.destroy();
        entry.state = reason ? 'unreachable' : 'reachable';
        entry.reason = reason;
        if (reason) console.log(`[REACHABILITY] ${host} is unreachable (${reason}); requests to it will be skipped`);
        var waiting = entry.waiting;
        entry.waiting = [];
        waiting.forEach(function(cb) { cb(reason); });
    };

    // Time only the TCP handshake. Name resolution runs on libuv's small thread
    // pool and queues behind every other lookup at scan start (median 13s, 90th
    // percentile 31s, for ~330 hosts at once, against a slowest handshake of
    // under 1s), so a clock started before it marks healthy endpoints down.
    var startConnectTimer = function() {
        connectTimer = setTimeout(function() {
            finish('no TCP connection within ' + (PROBE_TIMEOUT_MS / 1000) + 's');
        }, PROBE_TIMEOUT_MS);
    };
    if (net.isIP(host)) startConnectTimer();
    socket.on('lookup', function(err) { if (!err) startConnectTimer(); });

    socket.on('connect', function() { finish(null); });
    socket.on('error', function(err) {
        // A name that does not exist is unreachable. Any other lookup failure
        // (EAI_AGAIN from a busy resolver) says nothing about the endpoint, so
        // let its requests through and leave them to the SDK.
        if (err.syscall === 'getaddrinfo' && err.code !== 'ENOTFOUND') return finish(null);
        finish(err.code || err.message);
    });
};

// S3 puts the bucket in the hostname (bucket.s3.region.amazonaws.com). Probe
// the service endpoint instead, so it is checked once rather than per bucket.
var requestHost = function(request) {
    var host = request.httpRequest && request.httpRequest.endpoint && request.httpRequest.endpoint.hostname;
    var bucket = request.params && request.params.Bucket;
    if (host && bucket && host.indexOf(bucket + '.') === 0) host = host.slice(bucket.length + 1);
    return host;
};

/**
 * Checks a host before a request is sent to it, for clients outside aws-sdk v2.
 * @param callback Called with null if the host is reachable, otherwise with an
 * EndpointUnreachable error to record in place of the response.
 */
var check = function(host, callback) {
    if (proxyConfigured()) return callback(null);
    probe(host, function(reason) {
        if (!reason) return callback(null);
        hosts[host].skipped++;
        callback(unreachableError(host, reason));
    });
};

/**
 * Installs the check on every aws-sdk v2 request. 'sign' runs again on every
 * retry and redirect, so a request re-pointed at another host is checked too.
 * Install after the --regions guard so that it refuses a request first.
 */
var install = function(AWS) {
    if (installed) return;
    installed = true;

    if (proxyConfigured()) {
        console.log('[REACHABILITY] An HTTPS proxy is configured; endpoint reachability checks are off');
        return;
    }

    AWS.events.onAsync('sign', function(request, done) {
        var host = requestHost(request);
        if (!host) return done();
        check(host, done);
    });
};

// Prints the unreachable hosts and how many requests to each were skipped.
var logSummary = function() {
    var unreachable = Object.keys(hosts).filter(function(host) {
        return hosts[host].state === 'unreachable';
    });
    if (!unreachable.length) return;

    console.log(`[REACHABILITY] ${unreachable.length} unreachable endpoint(s) skipped:`);
    unreachable.forEach(function(host) {
        console.log(`[REACHABILITY]   ${host}: ${hosts[host].skipped} request(s) not sent (${hosts[host].reason})`);
    });
};

module.exports = {
    install: install,
    check: check,
    logSummary: logSummary
};
