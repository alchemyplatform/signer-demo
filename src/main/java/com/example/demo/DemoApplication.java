package com.example.demo;

import com.alchemy.aa.Stamper;
import com.alchemy.aa.Stamper.Stamp;
import com.alchemy.aa.client.HttpConfig;
import com.alchemy.aa.client.JacksonBodyHandlers;
import com.alchemy.aa.client.SignerClient;
import com.alchemy.aa.client.SignerClient.User;
import com.alchemy.aa.core.TekManager;
import com.auth0.jwt.JWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.subtle.EllipticCurves;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Optional;
import lombok.Builder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.web3j.crypto.RawTransaction;
import org.web3j.utils.Convert;

@RestController
@SpringBootApplication
public class DemoApplication {

    private final ObjectMapper objectMapper;

    /// Those are our OIDC request response definition.
    @Builder
    public record AuthRequest(String nonce) {
    }

    public record AuthResponse(String token) {
    }

    public DemoApplication(ObjectMapper objectMapper) {
        HttpConfig config = new HttpConfig("<YOUR_PRIVATE_KEY>");
        signerClient = new SignerClient(config);
        this.objectMapper = objectMapper;
    }

    public static void main(String[] args) throws GeneralSecurityException {
        // Needed to include this to enable server side encryption.
        TinkConfig.register();

        // Needed to include encryption provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        SpringApplication.run(DemoApplication.class, args);
    }

    @GetMapping("/user")
    /// This endpoint initialize a stamper for the user, and auth the user.
    public String user(@RequestParam(value = "email", defaultValue = "") String email) throws Exception {
        // initialize a tek manager. it will then be stored in stamper.

        TekManager tekManager = TekManager.initializeTekManager();

        this.stamper = new Stamper(tekManager);

        // This calls our OIDC connector to issue a jwt token.
        // CHANGE-ME: this should be replaced to how client initialized a jwt token.
        AuthRequest request = AuthRequest.builder().nonce(signerClient.targetPublicKeyHex(stamper)).build();

        AuthResponse response = auth(request);
        // Use SDK to auth user. after auth, stamper will hold the stamping key.
        this.signer = signerClient.authenticateWithJWT(stamper, response.token(), "andy", 6000);

        return objectMapper.writeValueAsString(this.signer);
    }

    /// This endpoint signs a transaction with stamper. In this Demo, it signs a
    /// 4337 User Operation.
    @GetMapping("/sign")
    public String sign(@RequestParam(value = "payload", defaultValue = "") String payload) throws Exception {

        // Construct a 4337 UserOpeartion and convert to Json format
        Bytes txn = constructTransaction(this.signer.address());

        System.out.println("txn: " + txn);
        // Sign the transaction.
        String signature = (signerClient.signEthTx(stamper, this.signer, txn));

        return signature;
    }

    /// This is call OIDC to generate a jwt token.
    /// Should contact Alchemy to add your ODIC connector and replace wth that URI.
    public AuthResponse auth(AuthRequest payload) throws IOException, InterruptedException {
        ObjectMapper objectMapper = new ObjectMapper();
        // CHANGE-ME: change to your OIDC connector
        URI uri = URI.create("https://eft-full-koi.ngrok-free.app/api/authenticate");
        HttpRequest http_request = HttpRequest.newBuilder().uri(uri).header("accept", "application/json")
                .header("content-type", "application/json")
                .method("POST", HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload))).build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(http_request,
                HttpResponse.BodyHandlers.ofString());

        String token = response.body();
        return objectMapper.readValue(token, AuthResponse.class);
    }

    /// This is simulating a prepareUO call to generate a UO. currently it is faked.
    private Bytes constructTransaction(String senderAddress) {
        BigInteger nonce = BigInteger.valueOf(0); // 交易序号，需要从链上查询
        BigInteger gasPrice = BigInteger.valueOf(2_000_000_000L); // 2 Gwei
        BigInteger gasLimit = BigInteger.valueOf(21000); // 转账一般为21000
        String toAddress = "0xRecipientAddress...";
        BigInteger value = BigInteger.valueOf(1_000_000_000_000_000_000L); // 1 ETH in wei

        RawTransaction rawTransaction = RawTransaction.createEtherTransaction(nonce, gasPrice, gasLimit, toAddress,
                value);
        long chainId = 1; // 1=Ethereum mainnet, 3=Ropsten, 5=Goerli 等
        byte[] encodedTxForSigning = org.web3j.crypto.TransactionEncoder.encode(rawTransaction, chainId);
        byte[] txHashForSigning = org.web3j.crypto.Hash.sha3(encodedTxForSigning);
        return Bytes.copyFrom(txHashForSigning);
    }

    /// Signer client is stateless and could be used the whole life cycle as server.
    private SignerClient signerClient;

    /// This is simulating a stored stamper. it is a per-user session per stamper. normally,
    /// it should be stored after user authed, and load for user sign txns.
    private Stamper stamper;

    /// This is simulating a authed user. it is a per-user session per stamper. normally,
    /// it should be stored after user authed, and load for user sign txns.
    private User signer;
}
