# Signer Demo

This repository demonstrates how to use Alchemy's Java Signer SDK to authenticate users and sign real transactions on the Ethereum Sepolia test network.

## Maven Dependency

```xml
<dependency>
    <groupId>com.alchemy.accountkit</groupId>
    <artifactId>signer-sdk</artifactId>
    <version>0.1.0-alpha-7880b179</version>
</dependency>
```

## Setup

1. **Create an Alchemy application**  
   Go to the [Alchemy dashboard](https://dashboard.alchemy.com/apps/new) and create a new application with both **Account Kit** and **Node API** enabled.

2. **Insert your API key**  
   In `DemoApplication`, replace every instance of `"<REPLACE_WITH_API_KEY>"` with the API key obtained from Step 1.

3. **Onboard your OIDC connector**  
   Contact the Alchemy team to register (onboard) your OIDC connector.

4. **Update OIDC configuration**  
   In `DemoApplication`, replace every `//CHANGE-ME` placeholder with the relevant OIDC setup. Ensure that you can obtain a valid JWT token from your OIDC connector, and note that the JWT’s nonce must be `sha256(tekManager.publicKey())`.

5. **Start the project**  
   See [Start the project](#start-the-project) below.

## Start the Project

```bash
mvn spring-boot:run
```

## Deep Dive

`DemoApplication` defines two primary endpoints: `/user` and `/sign`. Both are GET endpoints.

### Testing the Endpoints

You can test the endpoints using tools such as **curl** or **Postman**.

---

### The `/user` Endpoint

When you call `/user` (with no parameters), the demo:
1. Generates a **TekManager** object for each end user.
2. Requests a JWT from your OIDC provider.
3. Authenticates with Alchemy using `signerClient.authenticateWithJWT`.
4. Returns a **stamper** that can be used to stamp data and exchange it for a real signature.

**Example Request (curl)**:
```bash
curl -X GET "http://localhost:8888/user"
```

**Example Response**:
```json
{
  "credentialBundle": {
    "bundlePrivateKey": "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBaTF44aNZtZsBv/hBFjp9eNeRREOf05hyaOMoqtLRArA==",
    "bundlePublicKey": "A5Kc3SmkRr8Idoyf/mqSL97MKsXR5j0E4pmwsrcgb1oH"
  },
  "user": {
    "email": null,
    "userId": "dfc453cc-df55-4716-8a15-61492b4f0fcc",
    "orgId": "e34032d8-d42f-4980-9f07-b7b40f765789",
    "address": "0x7f9689C78B86B289531f4dA0abf686e55F20A744",
    "solanaAddress": "7YnJFzxkkEiRMxdRSz4cd4FUCidKQv2JfgD6QaGpCLhH"
  }
}
```

**Important**:  
Before you call `/sign`, make sure you fund the returned `address` with some test ETH. You can use the [Alchemy Sepolia faucet](https://www.alchemy.com/faucets/ethereum-sepolia).

---

### The `/sign` Endpoint

Use `/sign` to sign and broadcast an Ethereum (Sepolia) transaction for the user you retrieved in `/user`.

**Query Parameter**:
- `userId`: The `userId` from the `/user` endpoint’s response.

**What Happens**:
1. The application creates a sample Eth-Sepolia transaction.
2. Calls `signerClient.signEthTx` using the **stamper** from `/user` to sign the transaction.
3. Broadcasts the transaction to the Sepolia test network.

**Example Request (curl)**:
```bash
curl -X GET "http://localhost:8888/sign?userId=dfc453cc-df55-4716-8a15-61492b4f0fcc"
```

**Example Response** (Transaction Hash):
```
0x9ef79e1711c6f08a625bc03dc7766f30c75069dc3ce2b18db6f860ed80b4d3a9
```

You can track the transaction status on [Sepolia Etherscan](https://sepolia.etherscan.io/) by appending your returned hash to the Etherscan URL, for example:

```
https://sepolia.etherscan.io/tx/0x9ef79e1711c6f08a625bc03dc7766f30c75069dc3ce2b18db6f860ed80b4d3a9
```

A sample transaction screenshot:
![transaction.png](/transaction.png)

---

**Questions or Issues?**  
If you run into any problems or need help, please contact the Alchemy team or open an issue on this repository.