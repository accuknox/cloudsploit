var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');
var awsRegions = require(__dirname + '/../../../helpers/aws/regions.js');

module.exports = function(callKey, forceCloudTrail, AWSConfig, collection, retries, callback) {
    var s3 = new AWS.S3(AWSConfig);

    // Region allow-list (--regions). S3 is collected globally (listBuckets is
    // account-wide) and each bucket's per-bucket calls are made in the bucket's
    // own region. When a selection is active we resolve each bucket's region and
    // skip buckets outside it, so no API call is ever made in an unselected
    // region. null means "no restriction" (original behavior).
    var selectedRegions = helpers.getSelectedRegions ? helpers.getSelectedRegions() : null;

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

    // The original per-bucket call: try against the current (us-east-1) client
    // and, on a 301, look up the bucket's region and retry there. Used for
    // buckets whose region is 'global'/undetermined and for unrestricted scans.
    function makeStandardCall(bucket, bcb) {
        helpers.makeCustomCollectorCall(s3, callKey, {Bucket:bucket}, retries, null, null, null, function(bErr, bData) {
            if (bErr) {
                collection['s3'][callKey][AWSConfig.region][bucket].err = bErr;

                if (bErr.statusCode && bErr.statusCode == 301) {
                    helpers.makeCustomCollectorCall(s3, 'getBucketLocation', {Bucket:bucket}, retries, null, null, null, function(locErr, locData) {
                        if (locErr || !locData || !locData.LocationConstraint) return bcb();
                        // Special case where location constraint is EU - rewrite as eu-west-1
                        if (locData.LocationConstraint == 'EU') locData.LocationConstraint = 'eu-west-1';

                        var altAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
                        altAWSConfig.region = locData.LocationConstraint;
                        var s3Alt = new AWS.S3(altAWSConfig);

                        s3Alt[callKey]({Bucket:bucket}, function(altErr, altData){
                            if (altErr) {
                                collection['s3'][callKey][AWSConfig.region][bucket].err = altErr;
                            } else {
                                collection['s3'][callKey][AWSConfig.region][bucket].err = null;
                                collection['s3'][callKey][AWSConfig.region][bucket].data = altData;
                            }
                            bcb();
                        });
                    });
                } else {
                    bcb();
                }
            } else {
                collection['s3'][callKey][AWSConfig.region][bucket].data = bData;
                bcb();
            }
        });
    }

    // Fast path when the bucket's region is already known: call directly in that
    // region (no 301 probe). Only reached for regions in the selection.
    function callInRegion(bucket, bucketRegion, bcb) {
        var target = s3;
        if (bucketRegion !== AWSConfig.region) {
            var altAWSConfig = JSON.parse(JSON.stringify(AWSConfig));
            altAWSConfig.region = bucketRegion;
            target = new AWS.S3(altAWSConfig);
        }
        target[callKey]({Bucket:bucket}, function(err, data){
            if (err) collection['s3'][callKey][AWSConfig.region][bucket].err = err;
            else collection['s3'][callKey][AWSConfig.region][bucket].data = data;
            bcb();
        });
    }

    // Map an S3 LocationConstraint to a region id (mirrors getS3BucketLocation).
    function resolveRegionFromConstraint(constraint) {
        if (constraint === 'EU') constraint = 'eu-west-1';
        if (constraint && awsRegions.all.indexOf(constraint) > -1) return constraint;
        if (constraint) return 'global';
        return 'us-east-1';
    }

    // Resolve (and cache) a bucket's region once, shared across every S3
    // per-bucket call for this scan. getBucketLocation is called against the
    // us-east-1 client, which returns the constraint without a redirect. The
    // cache is non-enumerable so it never leaks into the serialized collection.
    if (!Object.prototype.hasOwnProperty.call(collection.s3, '_bucketRegionCache')) {
        Object.defineProperty(collection.s3, '_bucketRegionCache', {
            value: {}, enumerable: false, writable: true, configurable: true
        });
    }
    var locCache = collection.s3._bucketRegionCache;

    function resolveBucketRegion(bucket, cb) {
        if (Object.prototype.hasOwnProperty.call(locCache, bucket)) return cb(locCache[bucket]);

        // Reuse getBucketLocation data if that call was already gathered.
        var cached = collection.s3.getBucketLocation &&
            collection.s3.getBucketLocation[AWSConfig.region] &&
            collection.s3.getBucketLocation[AWSConfig.region][bucket] &&
            collection.s3.getBucketLocation[AWSConfig.region][bucket].data;
        if (cached) {
            var r = resolveRegionFromConstraint(cached.LocationConstraint);
            locCache[bucket] = r;
            return cb(r);
        }

        helpers.makeCustomCollectorCall(s3, 'getBucketLocation', {Bucket:bucket}, retries, null, null, null, function(locErr, locData) {
            if (locErr || !locData) { locCache[bucket] = null; return cb(null); }
            var resolved = resolveRegionFromConstraint(locData.LocationConstraint);
            locCache[bucket] = resolved;
            cb(resolved);
        });
    }

    async.eachLimit(knownBuckets, 10, function(bucket, bcb){
        collection['s3'][callKey][AWSConfig.region][bucket] = {};

        // No region allow-list: preserve the original probe-then-redirect flow.
        if (!selectedRegions || !selectedRegions.length) {
            return makeStandardCall(bucket, bcb);
        }

        // Allow-list active: resolve region first and skip out-of-region buckets
        // so no per-bucket API call hits an unselected region. Buckets that are
        // 'global' or whose region can't be determined fall back to the original
        // flow and are always processed.
        resolveBucketRegion(bucket, function(bucketRegion) {
            if (bucketRegion && bucketRegion !== 'global') {
                if (selectedRegions.indexOf(bucketRegion) === -1) {
                    delete collection['s3'][callKey][AWSConfig.region][bucket];
                    return bcb();
                }
                return callInRegion(bucket, bucketRegion, bcb);
            }
            makeStandardCall(bucket, bcb);
        });
    }, function(){
        callback();
    });
};
