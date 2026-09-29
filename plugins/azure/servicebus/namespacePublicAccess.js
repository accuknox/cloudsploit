var async = require('async');
var helpers = require('../../../helpers/azure');
var cidrHelper = require('../../../helpers/azure/functions');

module.exports = {
    title: 'Namespace Public Access',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensures that Azure Service Bus namespaces are not publicly accessible.',
    more_info: 'Using private endpoints for Azure Service Bus namespace improve security by enabling private network access, encrypting communication, and enhancing performance. They seamlessly integrate with virtual networks, ensuring compliance and suitability for hybrid cloud scenarios.',
    recommended_action: 'Ensure that Azure Service Bus namespaces are only accessible through private endpoints.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/private-link-service',
    apis: ['serviceBus:listNamespacesBySubscription', 'serviceBus:getNamespaceNetworkRuleSet'],
    realtime_triggers: ['microsoftservicebus:namespaces:write','microsoftservicebus:namespaces:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.serviceBus, function(location, rcb) {
            const namespaces = helpers.addSource(cache, source,
                ['serviceBus', 'listNamespacesBySubscription', location]);

            if (!namespaces) return rcb();


            if (namespaces.err || !namespaces.data) {
                helpers.addResult(results, 3, 'Unable to query Service Bus namespaces: ' + helpers.addError(namespaces), location);
                return rcb();
            }

            if (!namespaces.data.length) {
                helpers.addResult(results, 0, 'No existing Service Bus namespaces found', location);
                return rcb();
            }

            for (let namespace of namespaces.data) {
                
                const networkRules = helpers.addSource(cache, source,
                    ['serviceBus', 'getNamespaceNetworkRuleSet', location, namespace.id]);

                if (networkRules && networkRules.err) {
                    helpers.addResult(results, 3, 'Unable to query network rules for namespace: ' + helpers.addError(networkRules), location, namespace.id);
                    continue;
                }

                if (namespace.publicNetworkAccess && namespace.publicNetworkAccess.toLowerCase() === 'enabled') {

                    const isPremium = namespace.sku && namespace.sku.tier && namespace.sku.tier.toLowerCase() === 'premium';
                    const isSelectedNetworks = networkRules && networkRules.data &&
                        networkRules.data.defaultAction && networkRules.data.defaultAction.toLowerCase() === 'deny';

                    if (isPremium && isSelectedNetworks) {
                        const hasApprovedPrivateEndpoint = namespace.privateEndpointConnections &&
                            namespace.privateEndpointConnections.length > 0 &&
                            namespace.privateEndpointConnections.some(conn =>
                                conn.properties && conn.properties.privateLinkServiceConnectionState &&
                                conn.properties.privateLinkServiceConnectionState.status === 'Approved'
                            );

                        const hasVnetRules = networkRules.data.virtualNetworkRules &&
                            networkRules.data.virtualNetworkRules.length > 0;

                        const ipRules = networkRules.data.ipRules || [];
                        const hasRestrictedIpRules = ipRules.length > 0 &&
                            !ipRules.some(rule => cidrHelper.isOpenCidrRange(rule.ipMask || rule.ipAddressOrRange));

                        if (hasApprovedPrivateEndpoint || hasVnetRules || hasRestrictedIpRules) {
                            helpers.addResult(results, 0, 'Service bus namespace is only accessible through private endpoints', location, namespace.id);
                        } else {
                            helpers.addResult(results, 2, 'Service bus namespace publicly accessible', location, namespace.id);
                        }
                    } else {
                        let hasOpenCidr = false;
                        let hasIpRules = networkRules && networkRules.data && networkRules.data.ipRules && networkRules.data.ipRules.length > 0;

                        if (hasIpRules) {
                            for (let rule of networkRules.data.ipRules) {
                                if (cidrHelper.isOpenCidrRange(rule.ipMask || rule.ipAddressOrRange)) {
                                    hasOpenCidr = true;
                                    break;
                                }
                            }
                        }

                        if (hasIpRules && !hasOpenCidr) {
                            helpers.addResult(results, 0, 'Service bus namespace is only accessible through private endpoints', location, namespace.id);
                        } else {
                            helpers.addResult(results, 2, 'Service bus namespace is publicly accessible', location, namespace.id);
                        }
                    }
                } else {
                    helpers.addResult(results, 0, 'Service bus namespace is only accessible through private endpoints', location, namespace.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};