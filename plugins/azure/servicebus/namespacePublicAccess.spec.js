var expect = require('chai').expect;
var namespacePublicAccess = require('./namespacePublicAccess.js');

const namespaces = [
    {   
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test',
        name: 'test',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: false,
        provisioningState: 'Succeeded',
        status: 'Active'
    },
    {   
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test2',
        name: 'test2',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Disabled',
        disableLocalAuth: true,
        provisioningState: 'Succeeded',
        status: 'Active',
        encryption: {
            keySource: 'Microsoft.KeyVault',
            requireInfrastructureEncryption: false
        },
    },
    {   
        sku: { name: 'Basic', tier: 'Basic' },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test3',
        name: 'test3',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        disableLocalAuth: true,
        provisioningState: 'Succeeded',
        status: 'Active'
    },
    {   
        sku: { name: 'Premium', tier: 'Premium', capacity: 1 },
        id: '/subscriptions/234/myrg/providers/Microsoft.ServiceBus/namespaces/test4',
        name: 'test4',
        type: 'Microsoft.ServiceBus/Namespaces',
        location: 'East US',
        publicNetworkAccess: 'Enabled',
        provisioningState: 'Succeeded',
        status: 'Active',
        privateEndpointConnections: [
            {
                properties: {
                    privateLinkServiceConnectionState: { status: 'Approved' }
                }
            }
        ]
    },
];

const createCache = (namespaces, err, networkRules) => {
    const networkRuleSet = {};
    if (namespaces && networkRules) {
        namespaces.forEach((ns, i) => {
            if (networkRules[i] !== undefined) {
                networkRuleSet[ns.id] = networkRules[i];
            }
        });
    }

    return {
        serviceBus: {
            listNamespacesBySubscription: {
                'eastus': {
                    data: namespaces,
                    err: err
                }
            },
            getNamespaceNetworkRuleSet: {
                'eastus': networkRuleSet
            }
        }
    };
};

describe('namespacePublicAccess', function () {
    describe('run', function () {

        it('should give a passing result if no Service Bus namespaces are found', function (done) {
            const cache = createCache([], null);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Service Bus namespaces found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Service Bus namespaces', function (done) {
            const cache = createCache(null, ['error']);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Service Bus namespaces');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query network rules for namespace', function (done) {
            const cache = createCache([namespaces[0]], null, [{ err: ['error'], data: null }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query network rules for namespace');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if namespace is not publicly accessible', function (done) {
            const cache = createCache([namespaces[1]], null);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service bus namespace is only accessible through private endpoints');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if non-premium namespace is publicly accessible', function (done) {
            const cache = createCache([namespaces[2]], null, [{ data: { defaultAction: 'Allow', ipRules: [] }, err: null }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service bus namespace is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if non-premium namespace has restricted IP rules', function (done) {
            const cache = createCache([namespaces[2]], null, [{
                data: { defaultAction: 'Allow', ipRules: [{ ipMask: '192.168.1.0/24' }] },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service bus namespace is only accessible through private endpoints');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if non-premium namespace has open CIDR IP rule', function (done) {
            const cache = createCache([namespaces[2]], null, [{
                data: { defaultAction: 'Allow', ipRules: [{ ipMask: '0.0.0.0/0' }] },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service bus namespace is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if premium namespace has selected networks with approved private endpoint', function (done) {
            const cache = createCache([namespaces[3]], null, [{
                data: { defaultAction: 'Deny', ipRules: [], virtualNetworkRules: [] },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service bus namespace is only accessible through private endpoints');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if premium namespace has selected networks with VNet rules', function (done) {
            const cache = createCache([namespaces[0]], null, [{
                data: {
                    defaultAction: 'Deny',
                    ipRules: [],
                    virtualNetworkRules: [{ subnet: { id: '/subscriptions/234/subnets/mysubnet' } }]
                },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service bus namespace is only accessible through private endpoints');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if premium namespace has selected networks with restricted IP rules', function (done) {
            const cache = createCache([namespaces[0]], null, [{
                data: {
                    defaultAction: 'Deny',
                    ipRules: [{ ipMask: '10.0.0.0/8' }],
                    virtualNetworkRules: []
                },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service bus namespace is only accessible through private endpoints');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if premium namespace has selected networks with open CIDR IP rule and no other restrictions', function (done) {
            const cache = createCache([namespaces[0]], null, [{
                data: {
                    defaultAction: 'Deny',
                    ipRules: [{ ipMask: '0.0.0.0/0' }],
                    virtualNetworkRules: []
                },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service bus namespace publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if premium namespace has selected networks but no endpoints, VNet rules, or IP rules configured', function (done) {
            const cache = createCache([namespaces[0]], null, [{
                data: { defaultAction: 'Deny', ipRules: [], virtualNetworkRules: [] },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service bus namespace publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if premium namespace has all networks enabled and no IP rules', function (done) {
            const cache = createCache([namespaces[0]], null, [{
                data: { defaultAction: 'Allow', ipRules: [], virtualNetworkRules: [] },
                err: null
            }]);
            namespacePublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service bus namespace is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});