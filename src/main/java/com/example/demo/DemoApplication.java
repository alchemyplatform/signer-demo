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
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.util.Bytes;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.security.GeneralSecurityException;
import java.util.Optional;
import lombok.Builder;
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

	@Builder
	public record UserOperation(
			String sender,
			String nonce,
			Optional<String> factory,
			Optional<String> factoryData,
			String callData,
			String callGasLimit,
			String verificationGasLimit,
			String preVerificationGas,
			String maxFeePerGas,
			String maxPriorityFeePerGas,
			String paymasterVerificationGasLimit,
			Optional<String> paymasterPostOpGasLimit
	){}

	public DemoApplication(ObjectMapper objectMapper) {
		HttpConfig config = new HttpConfig(
				"<YOUR_API>"
		);
		signerClient = new SignerClient(config);
		this.objectMapper = objectMapper;
	}
	@Builder
	public record AuthRequest(
		String nonce
	){}

	public record AuthResponse(
			String token
	){}
	public static void main(String[] args) throws GeneralSecurityException {

		TinkConfig.register();
		SpringApplication.run(DemoApplication.class, args);
	}

	@GetMapping("/user")
	///  This endpoint initialize a stamper for the user, and auth the user.
	public String user(@RequestParam(value = "email", defaultValue = "") String email)
      throws Exception {
		// initialize a tek manager. it will then be stored in stamper.
		TekManager tekManager = TekManager.initializeTekManager();
		this.stamper = new Stamper(tekManager);

		// This calls our OIDC connector to issue a jwt token.
		// CHANGE-ME: this should be replaced to how client initialized a jwt token.
		AuthRequest request = AuthRequest.builder()
				.nonce(
						signerClient.targetPublicKeyHex(stamper)).build();

		AuthResponse response = auth(request);
		// Use SDK to auth user. after auth, stamper will hold the stamping key.
		this.signer = signerClient.authenticateWithJWT(stamper, response.token(), "andy", 6000);

		return "";
	}

	/// This endpoint signs a transaction with stamper. In this Demo, it signs a
	/// 4337 User Operation.
	@GetMapping("/sign")
	public String sign(@RequestParam(value = "payload", defaultValue = "") String payload)
      throws Exception {

		// Construct a 4337 UserOpeartion and convert to Json format
		UserOperation uo = constructUO(this.signer.address());
		String uo_str = objectMapper.writeValueAsString(uo);

		// Sign the transaction.
		String signature = String.valueOf(
        signerClient.signEthTx( stamper, this.signer, Bytes.copyFrom(uo_str.getBytes())));

		return signature;
	}

	/// This is call OIDC to generate a jwt token.
	/// Should contact Alchemy to add your ODIC connector and replace wth that URI.
	public AuthResponse auth(AuthRequest payload) throws IOException, InterruptedException {
		ObjectMapper objectMapper = new ObjectMapper();
		URI uri = URI.create("https://eft-full-koi.ngrok-free.app/api/authenticate");
		HttpRequest http_request = HttpRequest.newBuilder().uri(uri).header("accept", "application/json")
				.header("content-type", "application/json")
				.method("POST", HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload))).build();
		HttpResponse<String> response = HttpClient.newHttpClient().send(http_request, HttpResponse.BodyHandlers.ofString());

		String token = response.body();
		return objectMapper.readValue(token, AuthResponse.class);
	}

	/// This is simulating a prepareUO call to generate a UO. currently it is faked.
	private UserOperation constructUO(String senderAddress){
		return UserOperation.builder()
				.sender(senderAddress)
				.callData("0x8DD7712Fb61d27f6000000000000000000000000efa0a72e583ea2a0babb14b9ced339ba4367e24300000000000000000000000000000000000000000000000000b1a2bc2ec5000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000")
				.nonce("0x0")
				.callGasLimit("0x1234")
				.verificationGasLimit("0x1234")
				.maxFeePerGas("0x1234")
				.paymasterVerificationGasLimit("0x1234")
				.preVerificationGas("0x1234")
				.build();
	}

	/// Signer client is stateless and could be used the whole life cycle as server.
	private SignerClient signerClient;

	///  This is simulating a stored stamper. it is a per-user session per stamper. normally,
	/// it should be stored after user authed, and load for user sign txns.
	private Stamper stamper;

	///  This is simulating a authed user. it is a per-user session per stamper. normally,
	/// it should be stored after user authed, and load for user sign txns.
	private User signer;
}
