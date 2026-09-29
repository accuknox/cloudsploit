var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Batch Account Public Access',
    category: 'Batch',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that Batch accounts are not publicly accessible.',
    more_info: 'Disabling public access for your Azure Batch Account enhances security by restricting unauthorized access to resources. This setting ensures that only trusted, internal sources can interact with Batch services, protecting data from potential external threats.',
    recommended_action: 'Modify Batch account and disable public access.',
    link: 'https://learn.microsoft.com/en-us/azure/batch/public-network-access',
    apis: ['batchAccounts:list'],
    realtime_triggers: ['microsoftbatch:batchaccounts:write','microsoftbatch:batchaccounts:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.batchAccounts, function(location, rcb){

            var batchAccounts = helpers.addSource(cache, source,
                ['batchAccounts', 'list', location]);

            if (!batchAccounts) return rcb();

            if (batchAccounts.err || !batchAccounts.data) {
                helpers.addResult(results, 3, 'Unable to query for Batch accounts: ' + helpers.addError(batchAccounts), location);
                return rcb();
            }
            if (!batchAccounts.data.length) {
                helpers.addResult(results, 0, 'No existing Batch accounts found', location);
                return rcb();
            }

            for (let batchAccount of batchAccounts.data) { 
                if (!batchAccount.id) continue;
        
                if (batchAccount.publicNetworkAccess && 
                    batchAccount.publicNetworkAccess.toLowerCase() === 'enabled') {

                    let isPublic = true;
                    const accountAccess = batchAccount.networkProfile && batchAccount.networkProfile.accountAccess;
                    const nodeManagementAccess = batchAccount.networkProfile && batchAccount.networkProfile.nodeManagementAccess;
                    
                    let accountAccessRestricted = false;
                    let nodeManagementAccessRestricted = false;

                    // Check Account Access
                    if (accountAccess && accountAccess.ipRules && accountAccess.ipRules.length > 0) {
                        let hasAccountOpenCidr = false;
                        for (let rule of accountAccess.ipRules) {
                            if (rule.action && rule.action.toLowerCase() === 'allow' &&
                                helpers.isOpenCidrRange(rule.value)) {
                                hasAccountOpenCidr = true;
                                break;
                            }
                        }
                        if (!hasAccountOpenCidr) {
                            accountAccessRestricted = true;
                        }
                    }
                    
                    // Check Node Management Access
                    if (nodeManagementAccess && nodeManagementAccess.ipRules && nodeManagementAccess.ipRules.length > 0) {
                        let hasNodeOpenCidr = false;
                        for (let rule of nodeManagementAccess.ipRules) {
                            if (rule.action && rule.action.toLowerCase() === 'allow' &&
                                helpers.isOpenCidrRange(rule.value)) {
                                hasNodeOpenCidr = true;
                                break;
                            }
                        }
                        if (!hasNodeOpenCidr) {
                            nodeManagementAccessRestricted = true;
                        }
                    }
                    
                    // Both Account Access and Node Management Access must be restricted for it to be NOT public
                    // Or if Node Management Access is not configured, consider it restricted
                    if (accountAccessRestricted && (nodeManagementAccessRestricted || !nodeManagementAccess)) {
                        isPublic = false;
                    }

                    if (isPublic) {
                        helpers.addResult(results, 2, 'Batch account is publicly accessible', location, batchAccount.id);
                    } else {
                        helpers.addResult(results, 0, 'Batch account is not publicly accessible', location, batchAccount.id);
                    }
                } else {
                    helpers.addResult(results, 0, 'Batch account is not publicly accessible', location, batchAccount.id);
                }    
            }
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};