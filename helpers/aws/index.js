var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var api = require('./api.js');
var api_multipart = require('./api_multipart.js');
var regRegions = require('./regions.js');
var govRegions = require('./regions_gov.js');
var govRegionsFedRampEast1  = require('./regions_gov_fedramp_east_1.js');
var govRegionsFedRampWest1  = require('./regions_gov_fedramp_west_1.js');
var chinaRegions = require('./regions_china.js');

// Meta keys (not per-service scan lists) that must never be narrowed by a
// region allow-list: `default`/`all` are used for lookups and classification,
// and `optin` classifies opt-in regions for status/messaging.
var preserveRegionKeys = ['default', 'all', 'optin'];

// Given the full service -> regions map, return a copy narrowed to only the
// user-selected regions. Global/single-region services (IAM, S3, CloudFront,
// Route53, etc.) and the meta keys above are preserved as-is so global checks
// keep running regardless of which regions were selected.
var filterRegionsBySelection = function(regionsMap, selectedRegions) {
    var filtered = {};
    Object.keys(regionsMap).forEach(function(service) {
        var serviceRegions = regionsMap[service];
        if (preserveRegionKeys.indexOf(service) > -1 ||
            !Array.isArray(serviceRegions) ||
            serviceRegions.length <= 1) {
            filtered[service] = serviceRegions;
            return;
        }
        filtered[service] = serviceRegions.filter(function(region) {
            return selectedRegions.indexOf(region) > -1;
        });
    });
    return filtered;
};

var regions = function(settings) {
    var regionsMap;
    if (settings.govcloud && settings.is_fedramp_type_high && settings.LAMBDA_REGION == 'us-gov-east-1') regionsMap = govRegionsFedRampEast1;
    else if (settings.govcloud && settings.is_fedramp_type_high && settings.LAMBDA_REGION == 'us-gov-west-1') regionsMap = govRegionsFedRampWest1;
    else if (settings.govcloud) regionsMap = govRegions;
    else if (settings.china) regionsMap = chinaRegions;
    else regionsMap = regRegions;

    // Restrict metadata collection and plugin execution to a user-selected set
    // of regions (from the --regions flag). When unset, behavior is unchanged.
    if (settings && settings.regions && settings.regions.length) {
        return filterRegionsBySelection(regionsMap, settings.regions);
    }

    return regionsMap;
};

var helpers = {
    regions: regions,
    MAX_REGIONS_AT_A_TIME: 6,
    CLOUDSPLOIT_EVENTS_BUCKET: 'cloudsploit-engine-trails',
    CLOUDSPLOIT_EVENTS_SNS: 'aqua-cspm-sns-',
    ENCRYPTION_LEVELS: ['none', 'sse', 'awskms', 'awscmk', 'externalcmk', 'cloudhsm'],
    IAM_CONDITION_OPERATORS: {
        string: {
            Allow: ['StringEquals', 'StringEqualsIgnoreCase', 'StringLike'],
            Deny: ['StringNotEquals', 'StringNotEqualsIgnoreCase', 'StringNotLike']
        },
        arn: {
            Allow: ['ArnEquals', 'ArnLike'],
            Deny: ['ArnNotEquals', 'ArnNotLike']
        },
        ipaddress: {
            Allow: 'IpAddress',
            Deny: 'NotIpAddress'
        }
    },
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];
for (var a in api) helpers[a] = api[a];
for (var am in api_multipart) helpers[am] = api_multipart[am];

module.exports = helpers;