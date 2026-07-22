var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    // Account-level call collected under us-east-1, but any regional s3-control
    // endpoint serves it, so a restricted scan sends it from a selected region.
    var s3control = helpers.createRegionalClient('S3Control', AWSConfig, helpers.allowedRegion(AWSConfig.region));

    var accountId = collection.sts.getCallerIdentity[AWSConfig.region].data;
    collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId] = {};

    var params = {
        AccountId: accountId
    };

    helpers.makeCustomCollectorCall(s3control, 'getPublicAccessBlock', params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId].err = err;
        }
        if (data) collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId].data = data;
        callback();
    });
};