const expect = require("chai").expect;
const plugin = require("./recoveryVaultPrivateEndpoint");

const vaultId =
  "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/ExampleRG/providers/Microsoft.RecoveryServices/vaults/ExampleVault";
const location = "eastus";

function createCache(vaultData) {
  return {
    recoveryServiceVaults: {
      listBySubscriptionId: {
        [location]: { data: [{ id: vaultId }] },
      },
      getRecoveryServiceVault: {
        [location]: {
          [vaultId]: { data: vaultData },
        },
      },
    },
  };
}

describe("recoveryVaultPrivateEndpoint", function () {
  it("should FAIL when public access is enabled and no private endpoints", function (done) {
    const cache = createCache({
      publicNetworkAccess: "Enabled",
      privateEndpointStateForBackup: "None",
      privateEndpointStateForSiteRecovery: "None",
    });
    plugin.run(cache, {}, (err, results) => {
      expect(results[0].status).to.equal(2);
      expect(results[0].message).to.include("PUBLIC");
      done();
    });
  });

  it("should FAIL when public access is enabled and private endpoints exist", function (done) {
    const cache = createCache({
      publicNetworkAccess: "Enabled",
      privateEndpointStateForBackup: "Approved",
      privateEndpointStateForSiteRecovery: "None",
    });
    plugin.run(cache, {}, (err, results) => {
      expect(results[0].status).to.equal(2);
      expect(results[0].message).to.include(
        "private endpoints but public network access is still enabled"
      );
      done();
    });
  });

  it("should PASS (OK) when public access is disabled and private endpoints exist", function (done) {
    const cache = createCache({
      publicNetworkAccess: "Disabled",
      privateEndpointStateForBackup: "Approved",
      privateEndpointStateForSiteRecovery: "None",
    });
    plugin.run(cache, {}, (err, results) => {
      expect(results[0].status).to.equal(0);
      expect(results[0].message).to.include(
        "is private: public network access is disabled and private endpoints are configured"
      );
      done();
    });
  });

  it("should FAIL when public access is disabled and no private endpoints", function (done) {
    const cache = createCache({
      publicNetworkAccess: "Disabled",
      privateEndpointStateForBackup: "None",
      privateEndpointStateForSiteRecovery: "None",
    });
    plugin.run(cache, {}, (err, results) => {
      expect(results[0].status).to.equal(2);
      expect(results[0].message).to.include(
        "public network access disabled but NO private endpoints configured"
      );
      done();
    });
  });
});
