
var expect = require('chai').expect;
var batchAccountsPublicAccess = require('./batchAccountsPublicAccess');

const batchAccounts = [
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "publicNetworkAccess": "Disabled"
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test",
        "name": "test",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "publicNetworkAccess": "Enabled"
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test3",
        "name": "test3",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test3.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "publicNetworkAccess": "Enabled",
        "networkProfile": {
            "accountAccess": {
                "ipRules": [
                    {
                        "action": "Allow",
                        "value": "12.3.4.54"
                    }
                ]
            }
        }
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test4",
        "name": "test4",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test4.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "publicNetworkAccess": "Enabled",
        "networkProfile": {
            "accountAccess": {
                "ipRules": [
                    {
                        "action": "Allow",
                        "value": "0.0.0.0/0"
                    }
                ]
            }
        }
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test5",
        "name": "test5",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test5.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "publicNetworkAccess": "Enabled",
        "networkProfile": {
            "accountAccess": {
                "ipRules": [
                    {
                        "action": "Allow",
                        "value": "10.0.0.0/8"
                    }
                ]
            },
            "nodeManagementAccess": {
                "ipRules": [
                    {
                        "action": "Allow",
                        "value": "192.168.0.0/16"
                    }
                ]
            }
        }
    },
    {
        "id": "/subscriptions/1234566/resourceGroups/dummy/providers/Microsoft.Batch/batchAccounts/test6",
        "name": "test6",
        "type": "Microsoft.Batch/batchAccounts",
        "location": "eastus",
        "accountEndpoint": "test6.eastus.batch.azure.com",
        "nodeManagementEndpoint": "123456789.eastus.service.batch.azure.com",
        "publicNetworkAccess": "Enabled",
        "networkProfile": {
            "accountAccess": {
                "ipRules": [
                    {
                        "action": "Allow",
                        "value": "10.0.0.0/8"
                    }
                ]
            },
            "nodeManagementAccess": {
                "ipRules": [
                    {
                        "action": "Allow",
                        "value": "0.0.0.0/0"
                    }
                ]
            }
        }
    },
];

const createCache = (batchAccounts) => {
    return {
        batchAccounts: {
            list: {
                'eastus': {
                    data: batchAccounts
                }
            }
        }
    }
};

const createErrorCache = () => {
    return {
        batchAccounts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('batchAccountsPublicAccess', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for Batch accounts:', function (done) {
            const cache = createCache(null);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Batch accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no Batch account exist', function (done) {
            const cache = createCache([]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Batch accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Batch account is not publicly accessible', function (done) {
            const cache = createCache([batchAccounts[0]]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Batch account is publicly accessible', function (done) {
            const cache = createCache([batchAccounts[1]]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Batch account is publicly accessible but restricted to selected networks', function (done) {
            const cache = createCache([batchAccounts[2]]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Batch account is publicly accessible with open CIDR range', function (done) {
            const cache = createCache([batchAccounts[3]]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if both Account and Node Management access are restricted to selected networks', function (done) {
            const cache = createCache([batchAccounts[4]]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Batch account is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Node Management access has open CIDR even if Account access is restricted', function (done) {
            const cache = createCache([batchAccounts[5]]);
            batchAccountsPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Batch account is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});