var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');
var awsRegions = require(__dirname + '/../../../helpers/aws/regions.js');

// How S3 says "this bucket is not in the region you called". The first four are
// aws-sdk's own regionRedirectErrorCodes (lib/services/s3.js); buckets in opt-in
// regions (me-central-1, mx-central-1, ...) answer with the last one instead, a
// plain 400 the SDK does not treat as a redirect and therefore never follows.
var wrongRegionCodes = [
    'AuthorizationHeaderMalformed', 'BadRequest', 'PermanentRedirect', 301,
    'IllegalLocationConstraintException'
];

function isWrongRegion(err) {
    return !!err && (wrongRegionCodes.indexOf(err.code) > -1 || err.statusCode == 301);
}

module.exports = function(callKey, forceCloudTrail, AWSConfig, collection, retries, callback) {
    // Region allow-list (--regions). S3 is collected as a global service, so
    // AWSConfig.region is us-east-1 and every request made here - including the
    // ones made only to find out where a bucket lives - goes to us-east-1 and is
    // recorded by CloudTrail there; aws-sdk also re-sends a redirected request to
    // the bucket's own region, which records it there too. With a selection
    // active every request is sent from a selected region and no redirect is
    // followed out of the selection, so no S3 call lands in a region the user
    // excluded. null means "no restriction" (original behavior).
    var selectedRegions = helpers.getSelectedRegions ? helpers.getSelectedRegions() : null;
    var restricted = !!(selectedRegions && selectedRegions.length);

    // Region the requests originate from: the collection region normally, the
    // first selected region when the scan is restricted and doesn't include it.
    // Results stay keyed on AWSConfig.region either way so plugins keep finding
    // them where they expect.
    var homeRegion = (restricted && selectedRegions.indexOf(AWSConfig.region) === -1) ?
        selectedRegions[0] : AWSConfig.region;

    var clients = {};

    function clientFor(region) {
        if (!clients[region]) {
            var regionConfig = JSON.parse(JSON.stringify(AWSConfig));
            regionConfig.region = region;
            var client = new AWS.S3(regionConfig);

            // aws-sdk re-points S3 requests on its own in two places, and both
            // put a request in a region the scan excluded: it re-sends a
            // redirected call to the bucket's own region, and it rewrites any
            // request whose bucket is in its (process-wide, prototype-level)
            // bucketRegionCache. Under a selection the request has to stay in
            // the region it was aimed at - callAndLearnRegion() reads the
            // bucket's real region off the response instead.
            if (restricted) {
                client.retryableError = function(err, request) {
                    if (isWrongRegion(err)) return false;
                    return AWS.S3.prototype.retryableError.call(this, err, request);
                };
                client.correctBucketRegionFromCache = function() {};
            }

            clients[region] = client;
        }

        return clients[region];
    }

    var s3 = clientFor(homeRegion);
    var results = collection['s3'][callKey][AWSConfig.region];

    var knownBuckets = [];

    if (!forceCloudTrail && collection &&
        collection.s3 && collection.s3.listBuckets &&
        collection.s3.listBuckets[AWSConfig.region] &&
        collection.s3.listBuckets[AWSConfig.region].data &&
        collection.s3.listBuckets[AWSConfig.region].data.length) {
        knownBuckets = collection.s3.listBuckets[AWSConfig.region].data.map(function(bucket){
            return bucket.Name;
        });
    }

    if (collection && collection.cloudtrail &&
        collection.cloudtrail.describeTrails) {

        for (var region in collection.cloudtrail.describeTrails) {
            if (!collection.cloudtrail.describeTrails[region].data ||
                !collection.cloudtrail.describeTrails[region].data.length) continue;

            for (var t in collection.cloudtrail.describeTrails[region].data) {
                var trail = collection.cloudtrail.describeTrails[region].data[t];

                if (knownBuckets.indexOf(trail.S3BucketName) === -1) {
                    knownBuckets.push(trail.S3BucketName);
                }
            }
        }
    }

    if (!knownBuckets || !knownBuckets.length) return callback();

    // Bucket -> region learned earlier in this scan, shared by every S3
    // per-bucket call so only the first one pays for the discovery. Kept
    // non-enumerable so it never leaks into the serialized collection.
    if (!Object.prototype.hasOwnProperty.call(collection.s3, '_bucketRegionCache')) {
        Object.defineProperty(collection.s3, '_bucketRegionCache', {
            value: {}, enumerable: false, writable: true, configurable: true
        });
    }
    var locCache = collection.s3._bucketRegionCache;

    // The per-bucket call for unrestricted scans: try the home client and, when
    // the bucket turns out to live elsewhere, retry in its own region.
    function makeStandardCall(bucket, bcb) {
        helpers.makeCustomCollectorCall(s3, callKey, {Bucket:bucket}, retries, null, null, null, function(bErr, bData) {
            if (!bErr) {
                results[bucket].data = bData;
                return bcb();
            }

            results[bucket].err = bErr;

            if (!isWrongRegion(bErr)) return bcb();

            // aws-sdk follows most of these redirects itself, so reaching here
            // means it could not: either it never learned the region, or the
            // answer was an opt-in region's 400, which it does not act on. When
            // S3 reported the region (err.region, or the x-amz-bucket-region
            // header the SDK keeps in bucketRegionCache), retry straight there.
            var bucketRegion = bErr.region || s3.bucketRegionCache[bucket] || null;
            if (bucketRegion && bucketRegion !== homeRegion) return retryInRegion(bucket, bucketRegion, bcb);

            // It reported nothing, so ask where the bucket is and retry there.
            helpers.makeCustomCollectorCall(s3, 'getBucketLocation', {Bucket:bucket}, retries, null, null, null, function(locErr, locData) {
                if (locErr || !locData || !locData.LocationConstraint) return bcb();
                // Special case where location constraint is EU - rewrite as eu-west-1
                if (locData.LocationConstraint == 'EU') locData.LocationConstraint = 'eu-west-1';

                retryInRegion(bucket, locData.LocationConstraint, bcb);
            });
        });
    }

    // Second attempt for a bucket that lives in another region, in that region.
    function retryInRegion(bucket, bucketRegion, bcb) {
        clientFor(bucketRegion)[callKey]({Bucket:bucket}, function(altErr, altData){
            if (altErr) {
                results[bucket].err = altErr;
            } else {
                results[bucket].err = null;
                results[bucket].data = altData;
            }
            bcb();
        });
    }

    // Restricted flow. The call is made in `region` - always one the scan is
    // allowed to touch - and its answer says where the bucket actually lives:
    // S3 serves a bucket-level call only from the bucket's own region, so a
    // success means the bucket is here, and a redirect carries the real region
    // on err.region (the SDK records it in bucketRegionCache as well). That is
    // how a bucket's region is discovered under a selection: no getBucketLocation
    // probe, and nothing sent to a region outside the selection.
    function callAndLearnRegion(bucket, region, bcb) {
        var client = clientFor(region);

        helpers.makeCustomCollectorCall(client, callKey, {Bucket:bucket}, retries, null, null, null, function(err, data) {
            if (!err) {
                locCache[bucket] = region;
                results[bucket].data = data;
                return bcb();
            }

            // Where the bucket really lives comes back with the failure: on
            // err.region, or in the x-amz-bucket-region header the SDK records
            // in bucketRegionCache. The error code is not a reliable signal -
            // buckets in opt-in regions (me-central-1, mx-central-1, ...) answer
            // a cross-region call with a plain 400/403 rather than a redirect -
            // so trust the region S3 reported instead of the code.
            var bucketRegion = err.region || client.bucketRegionCache[bucket] || null;

            if (bucketRegion && bucketRegion !== region) {
                locCache[bucket] = bucketRegion;

                if (selectedRegions.indexOf(bucketRegion) === -1) {
                    skipOutOfRegion(bucket, bucketRegion);
                    return bcb();
                }

                return callInRegion(bucket, bucketRegion, bcb);
            }

            // A real error from the bucket's own region (access denied, no such
            // configuration, ...). The region is left uncached: guessing it here
            // would send the remaining per-bucket calls somewhere they don't
            // belong, and the next call re-probes from a selected region anyway.
            results[bucket].err = err;
            bcb();
        });
    }

    // A bucket outside the selection: nothing is collected for it. getBucketLocation
    // is the one call still worth answering, and it can be answered without a
    // request - the region came from S3's own x-amz-bucket-region header. Plugins
    // tag every S3 result with the bucket's region through that call, and the
    // engine needs that tag to keep the bucket out of a region-restricted report;
    // dropping the entry instead would leave the bucket tagged 'global' and its
    // "unable to obtain data" rows would survive the filter.
    function skipOutOfRegion(bucket, bucketRegion) {
        if (callKey !== 'getBucketLocation') {
            delete results[bucket];
            return;
        }

        // us-east-1 buckets report an empty constraint, as the real call does.
        results[bucket] = {
            data: {LocationConstraint: bucketRegion === 'us-east-1' ? '' : bucketRegion}
        };
    }

    // Region already known and inside the selection: call it directly, no probe.
    function callInRegion(bucket, bucketRegion, bcb) {
        helpers.makeCustomCollectorCall(clientFor(bucketRegion), callKey, {Bucket:bucket}, retries, null, null, null, function(err, data){
            if (err) results[bucket].err = err;
            else results[bucket].data = data;
            bcb();
        });
    }

    // Map an S3 LocationConstraint to a region id, or null when it isn't one we
    // recognize (mirrors getS3BucketLocation).
    function regionFromConstraint(constraint) {
        if (constraint === 'EU') constraint = 'eu-west-1';
        if (!constraint) return 'us-east-1';
        return awsRegions.all.indexOf(constraint) > -1 ? constraint : null;
    }

    // Region already known for this bucket, or null when it still has to be
    // discovered. getBucketLocation data collected earlier in the scan is free
    // to reuse, so prefer it over a probe.
    function knownRegionFor(bucket) {
        if (locCache[bucket]) return locCache[bucket];

        var collected = collection.s3.getBucketLocation &&
            collection.s3.getBucketLocation[AWSConfig.region] &&
            collection.s3.getBucketLocation[AWSConfig.region][bucket] &&
            collection.s3.getBucketLocation[AWSConfig.region][bucket].data;
        if (collected) {
            locCache[bucket] = regionFromConstraint(collected.LocationConstraint);
            return locCache[bucket];
        }

        return null;
    }

    async.eachLimit(knownBuckets, 10, function(bucket, bcb){
        results[bucket] = {};

        // No region allow-list: preserve the original probe-then-redirect flow.
        if (!restricted) return makeStandardCall(bucket, bcb);

        var bucketRegion = knownRegionFor(bucket);

        // Region not known yet - the call itself doubles as the probe.
        if (!bucketRegion) return callAndLearnRegion(bucket, homeRegion, bcb);

        if (selectedRegions.indexOf(bucketRegion) === -1) {
            skipOutOfRegion(bucket, bucketRegion);
            return bcb();
        }

        callInRegion(bucket, bucketRegion, bcb);
    }, function(){
        callback();
    });
};
