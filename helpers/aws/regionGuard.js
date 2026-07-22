var AWS = require('aws-sdk');

// Region allow-list (--regions) and the enforcement behind it.
//
// The selection is registered here once at scan start (engine.js), and
// registering it installs a process-wide guard on the AWS SDK: every request
// from every client, of every service, is checked as it is signed - which is
// also the point every retry passes through - and refused before a socket is
// opened if it is aimed at a region the user did not select. Collectors do not
// have to remember anything; there is one rule, in one place, and it covers the
// requests the SDK makes on its own as well as the ones we ask for.
//
// What is deliberately still allowed: global endpoints. iam.amazonaws.com,
// sts.amazonaws.com and cloudfront.amazonaws.com name no region, and the global
// checks that use them are meant to keep running under a selection. A request is
// treated as regional - and therefore constrained - when its endpoint names the
// region it is going to (ec2.eu-central-1.amazonaws.com), and always for S3,
// whose "global" endpoint still reaches a bucket that lives in one specific
// region.
//
// S3 also needs the SDK stopped from re-routing itself. It follows S3 region
// redirects (retryableError) and rewrites any request whose bucket is in its
// process-wide bucketRegionCache (correctBucketRegionFromCache), so a call aimed
// at one region gets re-sent to another. The guard would refuse those re-sends,
// but refusing produces errors where the collector wants a clean skip, so under
// a selection both mechanisms are switched off and the S3 collector reads a
// bucket's real region off the response instead.

var selectedRegions = null;
var installed = false;

// Requests the guard refused. Empty after a correct scan; anything in here is a
// collector trying to reach a region the user excluded.
var blockedRequests = [];

// Services whose requests are always treated as regional, whatever their
// endpoint looks like.
var alwaysRegional = ['s3', 's3control'];

// How S3 says "this bucket is not in the region you called". The first four are
// aws-sdk's own regionRedirectErrorCodes (lib/services/s3.js); buckets in opt-in
// regions (me-central-1, mx-central-1, ...) answer with the last one instead, a
// plain 400 the SDK does not treat as a redirect and therefore never follows.
var wrongRegionCodes = [
    'AuthorizationHeaderMalformed', 'BadRequest', 'PermanentRedirect', 301,
    'IllegalLocationConstraintException'
];

var isRestricted = function() {
    return !!(selectedRegions && selectedRegions.length);
};

var isSelected = function(region) {
    return !isRestricted() || selectedRegions.indexOf(region) > -1;
};

var isWrongRegionError = function(err) {
    return !!err && (wrongRegionCodes.indexOf(err.code) > -1 || err.statusCode == 301);
};

var getSelectedRegions = function() {
    return selectedRegions;
};

// The region a call should be sent from when the one it was configured with is
// not selected. Used for account-wide calls that any regional endpoint serves
// (S3 listBuckets, S3Control, EC2 describeRegions): only the endpoint moves,
// results stay keyed on the original region.
var allowedRegion = function(region) {
    if (isSelected(region)) return region;
    return selectedRegions[0];
};

function targetRegionOf(request) {
    if (request.httpRequest && request.httpRequest.region) return request.httpRequest.region;
    if (request.service && request.service.config) return request.service.config.region;
    return null;
}

function isRegionalRequest(request, region) {
    var service = request.service || {};
    if (alwaysRegional.indexOf(service.serviceIdentifier) > -1) return true;

    var endpoint = request.httpRequest && request.httpRequest.endpoint;
    var host = (endpoint && endpoint.host) || '';
    return host.indexOf(region) > -1;
}

// The one rule, applied to every request the SDK signs.
function enforceRegion(request) {
    if (!isRestricted()) return;

    var region = targetRegionOf(request);
    if (!region || isSelected(region)) return;
    if (!isRegionalRequest(request, region)) return;

    blockedRequests.push({
        service: (request.service && request.service.serviceIdentifier) || 'unknown',
        operation: request.operation,
        region: region,
        host: (request.httpRequest && request.httpRequest.endpoint && request.httpRequest.endpoint.host) || null
    });

    throw AWS.util.error(new Error(
        (request.operation || 'request') + ' was aimed at ' + region +
        ', which is outside the --regions selection'
    ), {code: 'RegionNotSelected', retryable: false});
}

// Installed once, on the SDK itself, so nothing has to opt in.
var install = function() {
    if (installed) return;
    installed = true;

    // AWS.events is added to every request of every client
    // (Service.addAllRequestListeners), and 'sign' runs again on each retry, so
    // a request that gets re-pointed between attempts is checked again.
    AWS.events.on('sign', enforceRegion);

    var originalRetryableError = AWS.S3.prototype.retryableError;
    AWS.S3.prototype.retryableError = function(err, request) {
        if (isRestricted() && isWrongRegionError(err)) return false;
        return originalRetryableError.call(this, err, request);
    };

    var originalCorrectBucketRegion = AWS.S3.prototype.correctBucketRegionFromCache;
    AWS.S3.prototype.correctBucketRegionFromCache = function(req) {
        if (isRestricted()) return;
        return originalCorrectBucketRegion.call(this, req);
    };
};

var setRegions = function(regionList) {
    selectedRegions = (Array.isArray(regionList) && regionList.length) ? regionList : null;
    if (isRestricted()) install();
};

// Convenience for building a client pinned to a specific region. The guard
// applies either way - this just keeps the region handling in one place.
var createClient = function(serviceName, AWSConfig, region) {
    var regionConfig = JSON.parse(JSON.stringify(AWSConfig));
    regionConfig.region = region;
    return new AWS[serviceName](regionConfig);
};

module.exports = {
    setRegions: setRegions,
    getSelectedRegions: getSelectedRegions,
    allowedRegion: allowedRegion,
    isWrongRegionError: isWrongRegionError,
    createClient: createClient,
    blockedRequests: blockedRequests
};
