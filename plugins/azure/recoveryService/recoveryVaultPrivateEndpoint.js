const async = require("async");
const helpers = require("../../../helpers/azure");

module.exports = {
  title: "Recovery Services Vault Private Endpoint",
  category: "Recovery Service Vault",
  domain: "Backup",
  severity: "High",
  description:
    "Ensure that Azure Recovery Services Vaults are not publicly accessible and have private endpoints configured.",
  more_info:
    "Private endpoints restrict access to the vault over a private network, reducing exposure to the public internet.",
  recommended_action:
    "Configure a private endpoint for the Recovery Services Vault.",
  link: "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview",
  apis: [
    "recoveryServiceVaults:getRecoveryServiceVault",
    "recoveryServiceVaults:listBySubscriptionId",
  ],
  realtime_triggers: [
    "microsoftrecoveryservices:vaults:write",
    "microsoftrecoveryservices:vaults:delete",
  ],

  run: function (cache, settings, callback) {
    const results = [];
    const source = {};
    const locations = helpers.locations(settings.govcloud);

    async.each(
      locations.recoveryServiceVaults,
      (location, rcb) => {
        const serviceVaults = helpers.addSource(cache, source, [
          "recoveryServiceVaults",
          "listBySubscriptionId",
          location,
        ]);

        if (!serviceVaults || serviceVaults.err || !serviceVaults.data)
          return rcb();

        for (let vault of serviceVaults.data) {
          if (!vault.id) continue;

          const getVault = helpers.addSource(cache, source, [
            "recoveryServiceVaults",
            "getRecoveryServiceVault",
            location,
            vault.id,
          ]);

          if (!getVault || getVault.err || !getVault.data) {
            helpers.addResult(
              results,
              3,
              "Unable to query Recovery Service Vault details: " +
                helpers.addError(getVault),
              location,
              vault.id
            );
            continue;
          }

          // Use new API response structure
          // Check for publicNetworkAccess property
          const publicAccess =
            typeof getVault.data.publicNetworkAccess === "string"
              ? getVault.data.publicNetworkAccess
              : "Enabled"; // Default to 'Enabled' if missing

          // Check for private endpoint states (new API: privateEndpointStateForBackup, privateEndpointStateForSiteRecovery)
          // Consider vault private if either backup or site recovery endpoint is not 'None'
          const backupPrivateState =
            getVault.data.privateEndpointStateForBackup || "None";
          const siteRecoveryPrivateState =
            getVault.data.privateEndpointStateForSiteRecovery || "None";
          const hasPrivate =
            backupPrivateState !== "None" ||
            siteRecoveryPrivateState !== "None";
          const isPublicDisabled = publicAccess.toLowerCase() === "disabled";

          if (hasPrivate && isPublicDisabled) {
            helpers.addResult(
              results,
              0,
              "Recovery Service Vault is private: public network access is disabled and private endpoints are configured",
              location,
              vault.id
            );
          } else if (!hasPrivate && isPublicDisabled) {
            helpers.addResult(
              results,
              2,
              "Recovery Service Vault has public network access disabled but NO private endpoints configured (not accessible)",
              location,
              vault.id
            );
          } else if (hasPrivate && !isPublicDisabled) {
            helpers.addResult(
              results,
              2,
              "Recovery Service Vault has private endpoints but public network access is still enabled (partially public)",
              location,
              vault.id
            );
          } else {
            helpers.addResult(
              results,
              2,
              "Recovery Service Vault is PUBLIC: no private endpoints and public network access is enabled",
              location,
              vault.id
            );
          }
        }
        rcb();
      },
      function () {
        callback(null, results, source);
      }
    );
  },
};
