var shared = require(__dirname + '/../shared.js');
var functions = require('./functions.js');
var regLocations = require('./locations.js');
var govLocations = require('./locations_gov.js');

// User-selected locations (from the --regions flag). Stored at module scope
// because plugins call locations(govcloud) without access to settings. Set once
// at scan start via setRegions(); null means "no restriction".
var selectedRegions = null;

var setRegions = function(regions) {
    selectedRegions = (Array.isArray(regions) && regions.length) ? regions : null;
};

// Meta keys that must never be narrowed by a location allow-list. `all` is the
// full list of every Azure location, used by plugins for lookups/coverage
// checks (e.g. verifying a log profile monitors every region) rather than as a
// per-service scan list, so it is preserved as-is.
var preserveLocationKeys = ['all'];

// Given the full service -> locations map, return a copy narrowed to only the
// user-selected locations. `global` entries are always kept so region-agnostic
// services (AAD, subscriptions, security center, etc.) keep running regardless
// of which locations were selected.
var filterLocationsBySelection = function(locationsMap, selected) {
    var filtered = {};
    Object.keys(locationsMap).forEach(function(service) {
        var serviceLocations = locationsMap[service];
        if (preserveLocationKeys.indexOf(service) > -1 ||
            !Array.isArray(serviceLocations)) {
            filtered[service] = serviceLocations;
            return;
        }
        filtered[service] = serviceLocations.filter(function(location) {
            return location === 'global' || selected.indexOf(location) > -1;
        });
    });
    return filtered;
};

var locations = function(govcloud) {
    var locationsMap = govcloud ? govLocations : regLocations;

    // Restrict plugin execution to a user-selected set of locations (from the
    // --regions flag). When unset, behavior is unchanged.
    if (selectedRegions && selectedRegions.length) {
        return filterLocationsBySelection(locationsMap, selectedRegions);
    }

    return locationsMap;
};

var helpers = {
    locations: locations,
    setRegions: setRegions
};

for (var s in shared) helpers[s] = shared[s];
for (var f in functions) helpers[f] = functions[f];

module.exports = helpers;
