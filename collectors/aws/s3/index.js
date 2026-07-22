var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');
var awsRegions = require(__dirname + '/../../../helpers/aws/regions.js');

module.exports = function(callKey, forceCloudTrail, AWSConfig, collection, retries, callback) {
    // Region allow-list (--regions); null means no restriction. S3 is collected
    // as a global service, so AWSConfig.region is us-east-1 - including for the
    // calls made only to find out where a bucket lives. Under a selection those
    // requests are sent from a selected region instead (see helpers/aws/
    // regionGuard.js), while results stay keyed on AWSConfig.region so plugins
    // keep finding them where they expect.
    var selectedRegions = helpers.getSelectedRegions();
    var restricted = !!(selectedRegions && selectedRegions.length);
    var homeRegion = helpers.allowedRegion(AWSConfig.region);

    var clients = {};

    function clientFor(region) {
        if (!clients[region]) clients[region] = helpers.createRegionalClient('S3', AWSConfig, region);
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

            if (!helpers.isWrongRegionError(bErr)) return bcb();

            // The bucket lives elsewhere and aws-sdk did not follow the redirect
            // itself - it never does for the 400 opt-in regions answer with. S3
            // reports the region on the error, or in the x-amz-bucket-region
            // header the SDK keeps in bucketRegionCache.
            var bucketRegion = bErr.region || s3.bucketRegionCache[bucket] || null;
            if (bucketRegion && bucketRegion !== homeRegion) return callInRegion(bucket, bucketRegion, bcb);

            // It reported nothing, so ask where the bucket is and retry there.
            helpers.makeCustomCollectorCall(s3, 'getBucketLocation', {Bucket:bucket}, retries, null, null, null, function(locErr, locData) {
                if (locErr || !locData || !locData.LocationConstraint) return bcb();
                // Special case where location constraint is EU - rewrite as eu-west-1
                if (locData.LocationConstraint == 'EU') locData.LocationConstraint = 'eu-west-1';

                callInRegion(bucket, locData.LocationConstraint, bcb);
            });
        });
    }

    // Runs the call in the region the bucket actually lives in.
    function callInRegion(bucket, bucketRegion, bcb) {
        helpers.makeCustomCollectorCall(clientFor(bucketRegion), callKey, {Bucket:bucket}, retries, null, null, null, function(err, data){
            if (err) {
                results[bucket].err = err;
            } else {
                results[bucket].err = null;
                results[bucket].data = data;
            }
            bcb();
        });
    }

    // Restricted flow: the call is made in `region` - always one the scan may
    // touch - and its answer says where the bucket really lives, so no separate
    // getBucketLocation probe is needed and nothing is sent outside the
    // selection. S3 serves a bucket-level call only from the bucket's own
    // region, so success means the bucket is here.
    function callAndLearnRegion(bucket, region, bcb) {
        var client = clientFor(region);

        helpers.makeCustomCollectorCall(client, callKey, {Bucket:bucket}, retries, null, null, null, function(err, data) {
            if (!err) {
                // getBucketLocation is the exception: every region answers it,
                // and the answer is the region itself. Trusting the call region
                // here would cache the wrong region for every bucket and send
                // the next per-bucket call to the wrong place.
                var learned = region;
                if (callKey === 'getBucketLocation' && data) {
                    learned = regionFromConstraint(data.LocationConstraint) || region;
                }

                locCache[bucket] = learned;
                results[bucket].data = data;
                return bcb();
            }

            // Where the bucket really lives comes back with the failure, on
            // err.region or in the header the SDK keeps in bucketRegionCache.
            // The error code is not a reliable signal (opt-in regions answer a
            // cross-region call with a plain 400), so trust the region instead.
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
            // configuration, ...). The region is left uncached rather than
            // guessed; the next call re-probes from a selected region anyway.
            results[bucket].err = err;
            bcb();
        });
    }

    // A bucket outside the selection: nothing is collected for it, except
    // getBucketLocation, which the region we just learned answers for free.
    // Plugins tag S3 results with the bucket's region through that call and the
    // engine needs the tag to filter the bucket out of the report - without it
    // the bucket is tagged 'global' and its rows survive the filter.
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
