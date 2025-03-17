# Signer Demo

This repo is a demo server that use alchemy's Java Signer SDK to auth user, and sign a real
transaction on Eth-Sepolia. 

## Maven repo
```shell
		<dependency>
			<groupId>com.alchemy.accountkit</groupId>
			<artifactId>signer-sdk</artifactId>
			<version>0.0</version>
		</dependency>
```

## Set up 
1. Create an alchemy project with `Account Kit` and `Node API` enabled. 
2. Replace all "<REPLACE_WITH_API_KEY>" in DemoApplication with the API key you get from step 1.
3. Contact Alchemy team to onboard your OIDC connector. 
4. Replace all "//CHANGE-ME" in DemoApplication with your OIDC setup. Make sure you can get a jwt token 
from the OIDC, and nonce of jwt be `sha256(tekManager.publicKey())`.

## Deep dive
This DemoApplication create 2 endpoints, `user` and `sign`. 


`user` demos an auth flow using Alchemy's 
Java SDK. It first generates a TekManager for each end user, and call OIDC to generate jwts. Then, 
use `signerClient.authenticateWithJWT` to auth user. After a success auth, a stamper will be available 
to stamp data and exchange the stamp to real signature. 
![user.png](/user.png)


`sign` demos a sign flow. Notice it has to get a stamper prior called. It first generates a transaction
on Eth-Sepolia, and call `signerClient.signEthTx` to sign the transaction with the stamper you grabbed 
from `user` endpoint. Then, broadcast it on chain. You'll get a transaction hash and could check the status
https://sepolia.etherscan.io/tx/<your-hash>.
![sign.png](/sign.png)

