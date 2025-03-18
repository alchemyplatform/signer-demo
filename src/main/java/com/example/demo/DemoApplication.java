package com.example.demo;

import com.alchemy.aa.Stamper;
import com.alchemy.aa.client.HttpConfig;
import com.alchemy.aa.client.SignerClient;
import com.alchemy.aa.client.SignerClient.User;
import com.alchemy.aa.core.TekManager;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.util.Bytes;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.HashMap;
import lombok.Builder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Convert;
import org.web3j.utils.Convert.Unit;

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

    public DemoApplication(ObjectMapper objectMapper) throws IOException {
        HttpConfig config = new HttpConfig("<REPLACE_WITH_API_KEY>");
        signerClient = new SignerClient(config);
        this.objectMapper = objectMapper;
        this.storage = new HashMap<>();
        this.web3j = Web3j.build(new HttpService("https://eth-sepolia.g.alchemy.com/v2/<REPLACE_WITH_API_KEY>"));
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
    public String user() throws Exception {
        // initialize a tek manager. it will then be stored in stamper.

        TekManager tekManager = TekManager.createNew();

        // This calls our OIDC connector to issue a jwt token.
        // CHANGE-ME: this should be replaced to how client initialized a jwt token.
        AuthRequest request = AuthRequest.builder().nonce(tekManager.publicKey()).build();

        AuthResponse response = auth(request);
        String jwtToken = response.token();
        // Use SDK to auth user. after auth, stamper will hold the stamping key.

        Stamper stamper = signerClient.authenticateWithJWT(tekManager, jwtToken, "andy", 6000);
        String jsonStampper = objectMapper.writeValueAsString(stamper);
        storage.put(stamper.getUser().userId(), jsonStampper);
        return objectMapper.writeValueAsString(stamper);
    }

    /// This endpoint signs a transaction with stamper. In this Demo, it signs an
    /// Eoa transaction.
    @GetMapping("/sign")
    public String sign(@RequestParam(value = "userId", defaultValue = "") String userId) throws Exception {

        // load stamper from stroage
        String jsonStampper = storage.get(userId);
        // deserialize from storage.
        Stamper stamper = objectMapper.readValue(jsonStampper, Stamper.class);

        RawTransaction rawTransaction = constructTransaction(stamper.getUser().address(),
                "0x8127382B4850527D0b94819606Ff2d7fF0f16E9d");
        Bytes txn = getEncodedTxForSigning(rawTransaction);

        // Sign the transaction.
        String signature = (signerClient.signEthTx(stamper, txn));

        SignatureData signatureData = getSignatureData(signature);

        byte[] signedTransaction = org.web3j.crypto.TransactionEncoder.encode(rawTransaction, signatureData);
        return broadcastSignedTransaction(signedTransaction);
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

    /// This method create an unsigned transaction.
    private RawTransaction constructTransaction(String senderAddress, String receiverAddress) throws IOException {

        long chainId = 11155111; // 11155111 Ethereum Sepolia

        BigInteger nonce = getAccountNonce(senderAddress); // Transaction Nonce
        BigInteger gasLimit = BigInteger.valueOf(50_000L);
        String toAddress = receiverAddress;
        BigInteger value = Convert.toWei("0.001", Convert.Unit.ETHER).toBigInteger(); // 0.001 ETH in wei
        BigInteger maxPriorityFeePerGas = Convert.toWei("30", Unit.GWEI).toBigInteger(); // 30 gwei
        BigInteger maxFeePerGas = Convert.toWei("30", Convert.Unit.GWEI).toBigInteger(); // 30 gwei

        return RawTransaction.createEtherTransaction(chainId, nonce, gasLimit, toAddress, value, maxPriorityFeePerGas,
                maxFeePerGas);
    }

    // A helper function to get sender's nonce
    private BigInteger getAccountNonce(String address) throws IOException {
        EthGetTransactionCount transactionCountResponse = web3j
                .ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).send();
        return transactionCountResponse.getTransactionCount();
    }

    // A helper function to encode txn for signing
    private Bytes getEncodedTxForSigning(RawTransaction rawTransaction) {
        byte[] encodedTxForSigning = org.web3j.crypto.TransactionEncoder.encode(rawTransaction);
        byte[] txHashForSigning = org.web3j.crypto.Hash.sha3(encodedTxForSigning);
        return Bytes.copyFrom(txHashForSigning);
    }

    // Convert signature to SignatureData structure.
    private SignatureData getSignatureData(String signature) {
        String sigHex = signature.replace("0x", ""); // remove leading 0x
        // r = [0..63] (64 hex chars => 32 bytes)
        String rHex = sigHex.substring(0, 64);
        // s = [64..127] (64 hex chars => 32 bytes)
        String sHex = sigHex.substring(64, 128);
        // v = [128..130] (2 hex chars => 1 byte)
        String vHex = sigHex.substring(128, 130);
        byte[] r = org.bouncycastle.util.encoders.Hex.decode(rHex);
        byte[] s = org.bouncycastle.util.encoders.Hex.decode(sHex);
        byte v = org.bouncycastle.util.encoders.Hex.decode(vHex)[0];
        return new org.web3j.crypto.Sign.SignatureData(v, r, s);
    }

    // broadcast transaction on chain.
    private String broadcastSignedTransaction(byte[] signedTransaction) throws IOException {
        EthSendTransaction response = web3j.ethSendRawTransaction(Hex.toHexString(signedTransaction)).send();
        if (response.hasError()) {
            System.err.println("Error: " + response.getError().getMessage());
            return "Error: " + response.getError().getMessage();
        } else {
            String txHash = response.getTransactionHash();
            return txHash;
        }
    }

    /// Signer client is stateless and could be used the whole life cycle as server.
    private SignerClient signerClient;

    /// This is simulating a storage of stamper.
    private HashMap<String, String> storage;

    /// This is a web3 connector to get and send transactions.
    private Web3j web3j;
}
