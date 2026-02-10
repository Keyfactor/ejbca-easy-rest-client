/*************************************************************************
 *                                                                       *
 *  Keyfactor Community                                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.ejbca.client.stress;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.SimpleDateFormat;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.json.simple.JSONObject;

import com.keyfactor.ejbca.client.ErceCommandBase;
import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

/**
 * This class provides the ability to use ERCE to perform a stress test against
 * EJBCA.
 */

public class X509StressTestCommand extends ErceCommandBase {

	private static final Logger log = Logger.getLogger(X509StressTestCommand.class);

	private static final String STRESS_TEST_PREFIX_DEFAULT = "ErceStressTest_";
	private static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll";
	private static final String REVOKE_URL_PREFIX = "/ejbca/ejbca-rest-api/v1/certificate/";
	private static final String REVOKE_URL_SUFFIX = "/revoke";
	private static final String REVOCATION_REASON = "UNSPECIFIED";

	private static final String CA_ARG = "--ca";
	private static final String CERTIFICATE_PROFILE_ARG = "--certificateprofile";
	private static final String END_ENTITY_PROFILE_ARG = "--endentityprofile";
	private static final String THREADS_ARG = "--threads";
	private static final String CERTS_PER_THREAD_ARG = "--certs";
	private static final String REUSE_KEY_ARG = "--singlekey";
	private static final String PREFIX_ARG = "--prefix";
	private static final String POSTFIX_ARG = "--postfix";
	private static final String KEYALG_ARG = "--keyalg";
	private static final String KEYSPEC_ARG = "--keyspec";
	private static final String SUBJECTDN_ARG = "--subjectdn";
	private static final String SAN_ARG = "--san";
	private static final String HISTORY_ARG = "--history";
	private static final String REVOKE_ARG = "--revoke";
	private static final String BACKDATEREVOKE_ARG = "--backdaterevoke";
	private static final String SAVECERTS_ARG = "--savecerts";
	private static final String REVOKEFILE_ARG = "--revokefile";
	private static final String OUTPUT_FORMAT_ARG = "--outputformat";
	private static final String OUTPUT_FILE_ARG = "--outputfile";
	private static final String PROGRESS_INTERVAL_ARG = "--progressinterval";
	private static final String SAVEKEYS_ARG = "--savekeys";
	private static final String LOADKEYS_ARG = "--loadkeys";

	private static final Set<String> RSA_KEY_SIZES = new LinkedHashSet<>(
			Arrays.asList("1024", "1536", "2048", "3072", "4096", "6144", "8192"));
	private static final Set<String> EC_CURVES = AlgorithmTools.getOnlyNamedEcCurvesMap().keySet();

	private String[][] payloads;
	private String[][] subjectDns;

	// Volatile counters for real-time progress tracking
	private volatile long totalIssuanceAttempts = 0;
	private volatile long totalSuccessfulIssuances = 0;
	private volatile long totalFailedIssuances = 0;
	private volatile long totalSuccessfulRevocations = 0;
	private volatile long totalFailedRevocations = 0;
	private volatile boolean stopProgressTracking = false;

	// Inner class to hold stress test results
	private static class StressTestResult {
		List<String> issuanceFailures;
		List<String> revocationFailures;
		List<CertificateInfo> issuedCertificates;

		StressTestResult(List<String> issuanceFailures, List<String> revocationFailures, List<CertificateInfo> issuedCertificates) {
			this.issuanceFailures = issuanceFailures;
			this.revocationFailures = revocationFailures;
			this.issuedCertificates = issuedCertificates;
		}
	}

	// Inner class to hold certificate information for saving/loading
	private static class CertificateInfo {
		String serialNumber;
		String issuerDn;

		CertificateInfo(String serialNumber, String issuerDn) {
			this.serialNumber = serialNumber;
			this.issuerDn = issuerDn;
		}

		// Parse from file format: serialNumber|issuerDn
		static CertificateInfo fromString(String line) {
			String[] parts = line.split("\\|", 2);
			if (parts.length == 2) {
				return new CertificateInfo(parts[0], parts[1]);
			}
			return null;
		}

		// Convert to file format: serialNumber|issuerDn
		@Override
		public String toString() {
			return serialNumber + "|" + issuerDn;
		}
	}

	{
		registerParameter(new Parameter(CA_ARG, "CA Name", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Name of the Certificate Authority to test against. Required for certificate issuance, not needed for --revokefile."));
		registerParameter(new Parameter(END_ENTITY_PROFILE_ARG, "End Entity Profile Name", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "End Entity Profile Name. Required for certificate issuance, not needed for --revokefile."));
		registerParameter(new Parameter(CERTIFICATE_PROFILE_ARG, "Certificate Profile Name", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Certificate Profile Name. Required for certificate issuance, not needed for --revokefile."));
		registerParameter(new Parameter(THREADS_ARG, "Numeric Value", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Number of threads."));
		registerParameter(new Parameter(CERTS_PER_THREAD_ARG, "Numeric Value", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Number CSRs to generate per thread. Required for certificate issuance, not needed for --revokefile."));
		registerParameter(new Parameter(REUSE_KEY_ARG, "", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.FLAG, "Set this flag to use the same key for all CSRs. Be aware that unique public keys must be disabled on the CA."));
		registerParameter(new Parameter(PREFIX_ARG, "prefix", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Optional prefix value for usernames and CNs. Default is '" + STRESS_TEST_PREFIX_DEFAULT + "'"));
		registerParameter(new Parameter(POSTFIX_ARG, "postfix", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Optional postfix value for usernames and CNs. Default is blank."));
		registerParameter(new Parameter(KEYALG_ARG, "cipher", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Key algorithm. Must be one of [ " + AlgorithmConstants.KEYALGORITHM_RSA + ", "
											+ AlgorithmConstants.KEYALGORITHM_EC + ", "
											+ AlgorithmConstants.KEYALGORITHM_ECDSA + ", "
											+ AlgorithmConstants.KEYALGORITHM_MLDSA44 + ", "
											+ AlgorithmConstants.KEYALGORITHM_MLDSA65 + ", "
											+ AlgorithmConstants.KEYALGORITHM_MLDSA87 + " ]. Default is ECDSA."));
		StringBuilder ecCurvesFormatted = new StringBuilder();
		ecCurvesFormatted.append("[");
		for (String curveName : EC_CURVES) {
			ecCurvesFormatted.append(" ").append(curveName).append(",");
		}
		ecCurvesFormatted.deleteCharAt(ecCurvesFormatted.lastIndexOf(","));
		ecCurvesFormatted.append(" ]");
		registerParameter(new Parameter(KEYSPEC_ARG, "Key Specification", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Key Specification.\n If cipher was RSA, must be one of [ 1024, 1536, 2048, 3072, 4096, 6144, 8192 ]. Default is 2048.\n If cipher was EC/ECDSA, must be one of "
						+ ecCurvesFormatted + ". Default is secp256r1.\n Should be omitted for ML-DSA variants."));
		registerParameter(new Parameter(SUBJECTDN_ARG, "Subject DN", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Optional Subject DN for certificates. If a CN attribute is present, the prefix and postfix will be applied to it. Default is 'CN=<prefix>_<threadId>_<certId>_<postfix>'."));
		registerParameter(new Parameter(SAN_ARG, "Subject Alternative Name", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Optional Subject Alternative Name (SAN) for certificates. Format: 'dnsName=example.com' or 'dnsName=example.com,ipAddress=192.168.1.1'. If a dnsName is provided, the prefix and postfix will be applied to it."));
		registerParameter(new Parameter(HISTORY_ARG, "Numeric Value", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Number of additional certificates to issue per end entity with unique keys. This allows testing certificate history in EJBCA. Default is 0 (no additional certificates)."));
		registerParameter(new Parameter(REVOKE_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Set this flag to revoke certificates after successful issuance. Useful for testing revocation performance and certificate lifecycle."));
		registerParameter(new Parameter(BACKDATEREVOKE_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.FLAG, "Set this flag along with --revoke to use the certificate's notBefore date for revocation instead of the current time. Allows backdated revocation for certificate profiles that permit it."));
		registerParameter(new Parameter(SAVECERTS_ARG, "filename", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Save issued certificate information (serial number and issuer DN) to specified file for later bulk revocation."));
		registerParameter(new Parameter(REVOKEFILE_ARG, "filename", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Perform bulk revocation of certificates listed in the specified file (created with --savecerts). When this flag is used, no new certificates are issued."));
		registerParameter(new Parameter(OUTPUT_FORMAT_ARG, "Output format", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Output format for test results. Options: 'console' (default), 'csv', 'markdown'. When csv or markdown is specified, --outputfile is required."));
		registerParameter(new Parameter(OUTPUT_FILE_ARG, "Output file", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "File path to save test results in CSV or Markdown format. Required when --outputformat is csv or markdown."));
		registerParameter(new Parameter(PROGRESS_INTERVAL_ARG, "Progress interval (seconds)", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Interval in seconds for displaying real-time progress updates. Default: 5 seconds. Set to 0 to disable progress updates."));
		registerParameter(new Parameter(SAVEKEYS_ARG, "directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Save all generated private keys to the specified directory as PEM files. Keys are named key_<algorithm>_<keyspec>_<threadId>_<keyIndex>.pem (e.g., key_ecdsa_secp256r1_0_0.pem). Useful for reusing keys in subsequent stress tests."));
		registerParameter(new Parameter(LOADKEYS_ARG, "directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Load pre-generated private keys from the specified directory instead of generating new ones. Significantly speeds up stress tests when testing large volumes (e.g., 10 million issuances). Keys should be named key_<algorithm>_<keyspec>_<threadId>_<keyIndex>.pem."));

	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		// Parse output format parameters (before mode check, needed for both modes)
		final String outputFormat = parameters.get(OUTPUT_FORMAT_ARG) != null ? parameters.get(OUTPUT_FORMAT_ARG) : "console";
		final String outputFile = parameters.get(OUTPUT_FILE_ARG);

		// Validate output format
		if (!outputFormat.equals("console") && !outputFormat.equals("csv") && !outputFormat.equals("markdown")) {
			log.error("Invalid output format: " + outputFormat + ". Must be 'console', 'csv', or 'markdown'");
			return CommandResult.CLI_FAILURE;
		}

		// Validate that outputFile is provided if format is csv or markdown
		if ((outputFormat.equals("csv") || outputFormat.equals("markdown")) && outputFile == null) {
			log.error("--outputfile is required when --outputformat is '" + outputFormat + "'");
			return CommandResult.CLI_FAILURE;
		}

		// Parse progress interval
		final int progressInterval;
		if (parameters.get(PROGRESS_INTERVAL_ARG) != null) {
			try {
				progressInterval = Integer.valueOf(parameters.get(PROGRESS_INTERVAL_ARG));
			} catch (NumberFormatException e) {
				log.error(PROGRESS_INTERVAL_ARG + " was not a numeric value");
				return CommandResult.CLI_FAILURE;
			}
			if (progressInterval < 0) {
				log.error(PROGRESS_INTERVAL_ARG + " must be non-negative");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			progressInterval = 5; // Default: 5 seconds
		}

		// Check if running in bulk revocation mode
		final String revokeFile = parameters.get(REVOKEFILE_ARG);
		final boolean isBulkRevocationMode = !StringUtils.isBlank(revokeFile);

		// Validate required parameters based on mode
		if (!isBulkRevocationMode) {
			// Enrollment mode: require CA, profiles, and certs parameters
			if (StringUtils.isBlank(parameters.get(CA_ARG))) {
				log.error(CA_ARG + " is required for certificate issuance. Use --help for more information.");
				return CommandResult.CLI_FAILURE;
			}
			if (StringUtils.isBlank(parameters.get(END_ENTITY_PROFILE_ARG))) {
				log.error(END_ENTITY_PROFILE_ARG + " is required for certificate issuance. Use --help for more information.");
				return CommandResult.CLI_FAILURE;
			}
			if (StringUtils.isBlank(parameters.get(CERTIFICATE_PROFILE_ARG))) {
				log.error(CERTIFICATE_PROFILE_ARG + " is required for certificate issuance. Use --help for more information.");
				return CommandResult.CLI_FAILURE;
			}
			if (StringUtils.isBlank(parameters.get(CERTS_PER_THREAD_ARG))) {
				log.error(CERTS_PER_THREAD_ARG + " is required for certificate issuance. Use --help for more information.");
				return CommandResult.CLI_FAILURE;
			}
		}

		// Parse thread count (required for both modes)
		final int numberOfThreads;
		try {
			numberOfThreads = Integer.valueOf(parameters.get(THREADS_ARG));
		} catch (NumberFormatException e) {
			log.error(THREADS_ARG + " was not a numeric value");
			return CommandResult.CLI_FAILURE;
		}
		if (numberOfThreads < 1) {
			log.error(THREADS_ARG + " must be a positive value");
			return CommandResult.CLI_FAILURE;
		}

		// Parse revocation flags
		final boolean backdateRevocation = parameters.containsKey(BACKDATEREVOKE_ARG);

		// If --revokefile is specified, perform bulk revocation instead of enrollment
		if (isBulkRevocationMode) {
			return performBulkRevocation(revokeFile, backdateRevocation, numberOfThreads, outputFormat, outputFile, progressInterval);
		}

		// Below this point: enrollment mode only
		final String endEntityProfileName = parameters.get(END_ENTITY_PROFILE_ARG);
		final String certificateProfileName = parameters.get(CERTIFICATE_PROFILE_ARG);
		final String caName = parameters.get(CA_ARG);
		final String prefix;
		if(parameters.containsKey(PREFIX_ARG)) {
			prefix = parameters.get(PREFIX_ARG);
		} else {
			prefix = STRESS_TEST_PREFIX_DEFAULT;
		}
		final String postfix;
		if(parameters.containsKey(POSTFIX_ARG)) {
			postfix = parameters.get(POSTFIX_ARG);
		} else {
			postfix = "";
		}

		final String subjectDn;
		if(parameters.containsKey(SUBJECTDN_ARG)) {
			subjectDn = parameters.get(SUBJECTDN_ARG);
		} else {
			subjectDn = null;
		}

		final String subjectAltName;
		if(parameters.containsKey(SAN_ARG)) {
			subjectAltName = parameters.get(SAN_ARG);
		} else {
			subjectAltName = null;
		}

		final int historyCount;
		if(parameters.containsKey(HISTORY_ARG)) {
			try {
				historyCount = Integer.valueOf(parameters.get(HISTORY_ARG));
			} catch (NumberFormatException e) {
				log.error(HISTORY_ARG + " was not a numeric value");
				return CommandResult.CLI_FAILURE;
			}
			if (historyCount < 0) {
				log.error(HISTORY_ARG + " must be a non-negative value");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			historyCount = 0;
		}

		final boolean revokeAfterIssuance = parameters.containsKey(REVOKE_ARG);
		final String saveCertsFile = parameters.get(SAVECERTS_ARG);
		final String saveKeysDir = parameters.get(SAVEKEYS_ARG);
		final String loadKeysDir = parameters.get(LOADKEYS_ARG);

		// Validate key directory parameters
		if (!StringUtils.isBlank(saveKeysDir) && !StringUtils.isBlank(loadKeysDir)) {
			log.error("Cannot use both " + SAVEKEYS_ARG + " and " + LOADKEYS_ARG + " at the same time.");
			return CommandResult.CLI_FAILURE;
		}

		if (!StringUtils.isBlank(saveKeysDir)) {
			File keysDir = new File(saveKeysDir);
			if (!keysDir.exists()) {
				if (!keysDir.mkdirs()) {
					log.error("Failed to create keys directory: " + saveKeysDir);
					return CommandResult.CLI_FAILURE;
				}
				log.info("Created keys directory: " + saveKeysDir);
			} else if (!keysDir.isDirectory()) {
				log.error(SAVEKEYS_ARG + " must be a directory: " + saveKeysDir);
				return CommandResult.CLI_FAILURE;
			}
		}

		if (!StringUtils.isBlank(loadKeysDir)) {
			File keysDir = new File(loadKeysDir);
			if (!keysDir.exists() || !keysDir.isDirectory()) {
				log.error(LOADKEYS_ARG + " directory does not exist: " + loadKeysDir);
				return CommandResult.CLI_FAILURE;
			}
		}

		// Parse and validate key algorithm
		String keyAlg = parameters.get(KEYALG_ARG);
		if (keyAlg == null) {
			keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA; // Default to ECDSA
		} else {
			switch (keyAlg.toUpperCase()) {
			case "RSA":
				keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
				break;
			case "EC":
			case "ECDSA":
				keyAlg = AlgorithmConstants.KEYALGORITHM_ECDSA;
				break;
			case AlgorithmConstants.KEYALGORITHM_MLDSA44:
				keyAlg = AlgorithmConstants.KEYALGORITHM_MLDSA44;
				break;
			case AlgorithmConstants.KEYALGORITHM_MLDSA65:
				keyAlg = AlgorithmConstants.KEYALGORITHM_MLDSA65;
				break;
			case AlgorithmConstants.KEYALGORITHM_MLDSA87:
				keyAlg = AlgorithmConstants.KEYALGORITHM_MLDSA87;
				break;
			default:
				log.error("Key Algorithm " + keyAlg + " was unknown.");
				return CommandResult.CLI_FAILURE;
			}
		}

		// Parse and validate key specification
		String keySpec = parameters.get(KEYSPEC_ARG);
		if (keySpec == null) {
			// Set defaults based on algorithm
			if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlg)) {
				keySpec = "2048";
			} else if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlg) || AlgorithmConstants.KEYALGORITHM_EC.equals(keyAlg)) {
				keySpec = "secp256r1";
			}
			// ML-DSA variants don't need a keySpec
		} else {
			// Validate key specification based on algorithm
			if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlg)) {
				if (!RSA_KEY_SIZES.contains(keySpec)) {
					log.error("Key size " + keySpec + " is invalid for RSA Keys.");
					return CommandResult.CLI_FAILURE;
				}
			} else if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlg) || AlgorithmConstants.KEYALGORITHM_EC.equals(keyAlg)) {
				if (!EC_CURVES.contains(keySpec)) {
					log.error(keySpec + " is not a known EC curve.");
					return CommandResult.CLI_FAILURE;
				}
			}
		}

		final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL)
				.toString();

		final int requestPerThread;
		try {
			requestPerThread = Integer.valueOf(parameters.get(CERTS_PER_THREAD_ARG));
		} catch (NumberFormatException e) {
			log.error(CERTS_PER_THREAD_ARG + " was not a numeric value");
			return CommandResult.CLI_FAILURE;
		}
		if (requestPerThread < 1) {
			log.error(CERTS_PER_THREAD_ARG + " must be a positive value");
			return CommandResult.CLI_FAILURE;
		}

		final boolean singleKey = parameters.containsKey(REUSE_KEY_ARG);

		try {
			generatePayloads(numberOfThreads, requestPerThread, caName, certificateProfileName, endEntityProfileName, singleKey, prefix, postfix, keyAlg, keySpec, subjectDn, subjectAltName, historyCount, saveKeysDir, loadKeysDir);
		} catch (IllegalStateException e) {
			getLogger().error("Failed to generate payloads: " + e.getMessage());
			return CommandResult.CLI_FAILURE;
		}
		log.info("All CSR payloads transferred to caches..\n\nPreparing orbital bombardment in....");
		try {
			for (int i = 3; i > 0; --i) {
				log.info(i + "...");
				Thread.sleep(500);
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			getLogger().error("Stress test interrupted: " + e.getMessage());
			return CommandResult.CLI_FAILURE;
		}
		
		log.info("\nWeapons free. Fire for effect.");

		// Calculate total payloads per thread considering history certificates
		final int certsPerEntity = 1 + historyCount;
		final int totalPayloadsPerThread = requestPerThread * certsPerEntity;
		final long expectedTotalCerts = (long) numberOfThreads * requestPerThread * certsPerEntity;

		// Reset counters
		totalIssuanceAttempts = 0;
		totalSuccessfulIssuances = 0;
		totalFailedIssuances = 0;
		totalSuccessfulRevocations = 0;
		totalFailedRevocations = 0;
		stopProgressTracking = false;

		// Start progress tracking thread if enabled
		Thread progressThread = null;
		if (progressInterval > 0) {
			progressThread = new Thread(() -> {
				long lastAttempts = 0;
				long lastTime = System.currentTimeMillis();

				while (!stopProgressTracking) {
					try {
						Thread.sleep(progressInterval * 1000L);

						if (stopProgressTracking) {
							break;
						}

						long currentTime = System.currentTimeMillis();
						long currentAttempts = totalIssuanceAttempts;
						long intervalAttempts = currentAttempts - lastAttempts;
						double intervalSeconds = (currentTime - lastTime) / 1000.0;
						double certsPerSec = intervalSeconds > 0 ? intervalAttempts / intervalSeconds : 0;

						if (revokeAfterIssuance) {
							System.out.println(String.format("Progress: %d/%d certs (%d successful, %d failed), %d revoked (%d successful, %d failed) - %.2f certs/s",
									currentAttempts, expectedTotalCerts, totalSuccessfulIssuances, totalFailedIssuances,
									totalSuccessfulRevocations + totalFailedRevocations, totalSuccessfulRevocations, totalFailedRevocations,
									certsPerSec));
						} else {
							System.out.println(String.format("Progress: %d/%d certs (%d successful, %d failed) - %.2f certs/s",
									currentAttempts, expectedTotalCerts, totalSuccessfulIssuances, totalFailedIssuances, certsPerSec));
						}

						lastAttempts = currentAttempts;
						lastTime = currentTime;
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						break;
					}
				}
			});
			progressThread.setDaemon(true);
			progressThread.start();
		}

		long startTime = System.currentTimeMillis();
		List<CompletableFuture<StressTestResult>> futures = new ArrayList<>();
		for (int threadNumber = 0; threadNumber < numberOfThreads; ++threadNumber) {
			final int row = threadNumber;
			futures.add(CompletableFuture.supplyAsync(() -> {

				List<String> issuanceFailures = new ArrayList<>();
				List<String> revocationFailures = new ArrayList<>();
				List<CertificateInfo> issuedCertificates = new ArrayList<>();
				for (int i = 0; i < totalPayloadsPerThread; ++i) {
					String payload = payloads[row][i];
					String certSubjectDn = subjectDns[row][i];
					String cnInfo = extractCNForErrorMessage(certSubjectDn);
					final HttpPost request = new HttpPost(restUrl);

					// Increment attempt counter
					synchronized (X509StressTestCommand.this) {
						totalIssuanceAttempts++;
					}

					try {
						request.setEntity(new StringEntity(payload));
						// connect to EJBCA and send the CSR and get an issued certificate back
						try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
							final InputStream entityContent = response.getEntity().getContent();
							String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
							switch (response.getStatusLine().getStatusCode()) {
							case 404:
								String msg404 =  "Thread ID: " + row + ", Iteration: " + i + cnInfo + " - Return code was: 404: " + responseString;
								getLogger().error(msg404);
								issuanceFailures.add(msg404);
								synchronized (X509StressTestCommand.this) {
									totalFailedIssuances++;
								}
								break;
							case 200:
							case 201:
								// Certificate issued successfully
								try {
									final JSONParser jsonParser = new JSONParser();
									final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(responseString);
									final String base64cert = (String) actualJsonObject.get("certificate");
									byte[] certBytes = Base64.decode(base64cert.getBytes());
									X509Certificate certificate = CertTools.getCertfromByteArray(certBytes, X509Certificate.class);

									// Track issued certificate
									String serialNumber = CertTools.getSerialNumberAsString(certificate);
									String issuerDn = CertTools.getIssuerDN(certificate);
									issuedCertificates.add(new CertificateInfo(serialNumber, issuerDn));

									// Increment successful issuance counter
									synchronized (X509StressTestCommand.this) {
										totalSuccessfulIssuances++;
									}

									// Revoke if requested
									if (revokeAfterIssuance) {
										revokeCertificate(certificate, issuerDn, serialNumber, backdateRevocation, row, i, cnInfo, revocationFailures);
									}
								} catch (ParseException | CertificateParsingException e) {
									String msgParseError = "Thread ID: " + row + ", Iteration: " + i + cnInfo + " - Failed to parse certificate: " + e.getMessage();
									getLogger().error(msgParseError);
									issuanceFailures.add(msgParseError);
									synchronized (X509StressTestCommand.this) {
										totalFailedIssuances++;
									}
								}
								break;
							default:
								String msgOthers = "Thread ID: " + row + ", Iteration: " + i + cnInfo + " - Return code was: " + response.getStatusLine().getStatusCode() + ": "
										+ responseString;
								getLogger().error(msgOthers);
								issuanceFailures.add(msgOthers);
								synchronized (X509StressTestCommand.this) {
									totalFailedIssuances++;
								}
								break;
							}
						} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException
								| KeyStoreException e) {
							getLogger().error("Could not perform request: " + e.getMessage());
							synchronized (X509StressTestCommand.this) {
								totalFailedIssuances++;
							}
						}
					} catch (IOException e) {
						getLogger().error("Could not perform request: " + e.getMessage());
						synchronized (X509StressTestCommand.this) {
							totalFailedIssuances++;
						}
					}
				}
				return new StressTestResult(issuanceFailures, revocationFailures, issuedCertificates);
			}));

		}
		CompletableFuture<Void> allFutures = CompletableFuture.allOf(futures.toArray(CompletableFuture<?>[]::new));
		List<String> issuanceResults = new ArrayList<>();
		List<String> revocationResults = new ArrayList<>();
		List<CertificateInfo> allIssuedCertificates = new ArrayList<>();
		allFutures.thenRun(() -> {
			for (CompletableFuture<StressTestResult> completedFuture : futures) {
				try {
					StressTestResult result = completedFuture.get();
					issuanceResults.addAll(result.issuanceFailures);
					revocationResults.addAll(result.revocationFailures);
					allIssuedCertificates.addAll(result.issuedCertificates);
				} catch (ExecutionException | InterruptedException e) {
					log.error("Future could not execute.", e);
				}
			}
		});

		allFutures.join();
		long endTime = System.currentTimeMillis();

		// Stop progress tracking
		stopProgressTracking = true;

		log.info("Fire mission complete. Weapons hold.\n");

		if(!issuanceResults.isEmpty()) {
			log.info("The following threads did not return a certificate:");
			for(String error : issuanceResults) {
				log.info(error);
			}
		}

		if(!revocationResults.isEmpty()) {
			log.info("\nThe following certificates failed to revoke:");
			for(String error : revocationResults) {
				log.info(error);
			}
		}

		final int certsPerEntityFinal = 1 + historyCount;
		long totalCerts = numberOfThreads * requestPerThread * certsPerEntityFinal;
		long totalEntities = numberOfThreads * requestPerThread;
		long successfulIssuances = totalCerts - issuanceResults.size();
		long duration = endTime - startTime;
		double executionTime =  duration / 1000.0;
		log.info("Total execution time: " + executionTime + " seconds.");
		if(successfulIssuances > 0) {
			double averageTime = executionTime / successfulIssuances;
			log.info("Average issuance time: " + averageTime + " seconds.");
			log.info("Throughput: " + 1 / averageTime + " certificates issued per second.");
		}
		log.info((successfulIssuances) + " certificates were successfully issued, with " + issuanceResults.size() + " issuance failures.");
		long successfulRevocations = 0;
		if(revokeAfterIssuance) {
			successfulRevocations = successfulIssuances - revocationResults.size();
			log.info((successfulRevocations) + " certificates were successfully revoked, with " + revocationResults.size() + " revocation failures.");
		}
		if(historyCount > 0) {
			log.info("Total end entities: " + totalEntities + " (" + certsPerEntityFinal + " certificate(s) per entity).");
		}

		// Save certificates if requested
		if (!StringUtils.isBlank(saveCertsFile) && !allIssuedCertificates.isEmpty()) {
			saveCertificatesToFile(allIssuedCertificates, saveCertsFile);
		}

		// Write results to file if requested
		if (outputFormat.equals("csv")) {
			try {
				writeIssuanceResultsToCsv(outputFile, totalCerts, successfulIssuances, issuanceResults.size(),
						successfulRevocations, revocationResults.size(), duration, revokeAfterIssuance);
				log.info("Results saved to " + outputFile);
			} catch (IOException e) {
				log.error("Failed to write CSV results to file: " + e.getMessage());
				return CommandResult.CLI_FAILURE;
			}
		} else if (outputFormat.equals("markdown")) {
			try {
				writeIssuanceResultsToMarkdown(outputFile, totalCerts, successfulIssuances, issuanceResults.size(),
						successfulRevocations, revocationResults.size(), duration, revokeAfterIssuance);
				log.info("Results saved to " + outputFile);
			} catch (IOException e) {
				log.error("Failed to write Markdown results to file: " + e.getMessage());
				return CommandResult.CLI_FAILURE;
			}
		}

		return CommandResult.SUCCESS;
	}

	@Override
	public String getFullHelpText() {
		StringBuilder sb = new StringBuilder();
		sb.append(getCommandDescription() + "\n\n");
		sb.append(
				"This command will spin up an n number of threads, which will submit an x number of pre-generated CSRs each against the given CA.\n");
		sb.append("By default, keys generated for each CSR will use ECDSA with the secp256r1 curve.\n");
		sb.append("You can configure the key algorithm using " + KEYALG_ARG + " (RSA, ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87) ");
		sb.append("and key specification using " + KEYSPEC_ARG + " (RSA key size or EC curve name).\n\n");
		sb.append("KEY REUSE FOR LARGE-SCALE TESTING:\n");
		sb.append("For large-scale stress tests (e.g., 10 million issuances), key generation can be a bottleneck.\n");
		sb.append("Use " + SAVEKEYS_ARG + " <directory> to save generated private keys to PEM files during the first run.\n");
		sb.append("Use " + LOADKEYS_ARG + " <directory> to load pre-generated keys in subsequent runs, significantly reducing preparation time.\n");
		sb.append("Keys are named key_<algorithm>_<keyspec>_<threadId>_<keyIndex>.pem (e.g., key_ecdsa_secp256r1_0_0.pem, key_rsa_2048_0_0.pem, key_ml-dsa-44_0_0.pem).\n\n");
		sb.append(
				"To allow for easy cleaning of the database afterwards, all end entities will have their usernames prefixed with "
						+ STRESS_TEST_PREFIX_DEFAULT + " by default.\n");
		sb.append("You can then clean the database using the following SQL commands: \n");
		sb.append("    " + "DELETE FROM CertificateData WHERE username LIKE '" + STRESS_TEST_PREFIX_DEFAULT + "%';\n");
		sb.append("    " + "DELETE FROM UserData WHERE username LIKE '" + STRESS_TEST_PREFIX_DEFAULT + "%';\n");
		sb.append("Note that audit logs should not be cleaned during this process.\n\n");
		sb.append("DO NOT use this command in a production database.\n");
		return sb.toString();
	}

	@Override
	public String getMainCommand() {
		return "stress";
	}

	@Override
	public String getCommandDescription() {
		return "Stress test command - will submit a multitude of certificate requests to EJBCA in parallel.";
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

	@SuppressWarnings("unchecked")
	private void generatePayloads(final int numberOfThreads, final int requestPerThread, final String caName,
			final String certificateProfileName, final String endEntityProfileName, final boolean singleKey, final String prefix, final String postfix, final String keyAlg, final String keySpec, final String customSubjectDn, final String customSubjectAltName, final int historyCount, final String saveKeysDir, final String loadKeysDir) {
		// Calculate total certificates: base certificates + additional history certificates
		final int certsPerEntity = 1 + historyCount;
		final int totalCertsPerThread = requestPerThread * certsPerEntity;

		log.info("Will submit a total of " + (requestPerThread * numberOfThreads * certsPerEntity) + " CSRs, using " + numberOfThreads
				+ " threads.");
		if (historyCount > 0) {
			log.info("Certificate history testing enabled: " + certsPerEntity + " certificate(s) per end entity (" + historyCount + " additional).");
		}

		// Log key loading/saving mode
		if (!StringUtils.isBlank(loadKeysDir)) {
			log.info("Loading pre-generated keys from: " + loadKeysDir);
		} else if (!StringUtils.isBlank(saveKeysDir)) {
			log.info("Will save generated keys to: " + saveKeysDir);
		}

		log.info("Pre generating CSR payloads...");
		final String password = "foo123";
		this.payloads = new String[numberOfThreads][totalCertsPerThread];
		this.subjectDns = new String[numberOfThreads][totalCertsPerThread];
		final int increment = numberOfThreads / 10;
		int counter = 0;
		KeyPair keyPair = null;
		try {
			int payloadIndex = 0;
			for (int i = 0; i < numberOfThreads; ++i) {
				payloadIndex = 0;
				for (int j = 0; j < requestPerThread; ++j) {
					final String endEntityName = prefix + "_" + i + "_" + j + (StringUtils.isEmpty(postfix) ? "" : "_" + postfix);
					final String subjectDn;
					final String subjectAltName;

					if (customSubjectAltName != null) {
						// Use custom SAN and apply prefix/postfix to dnsName if present
						subjectAltName = applyPrefixPostfixToSAN(customSubjectAltName, prefix, postfix, i, j);

						if (customSubjectDn != null) {
							// Both SAN and DN provided: use custom DN with prefix/postfix
							subjectDn = applyPrefixPostfixToCN(customSubjectDn, prefix, postfix, i, j);
						} else {
							// Only SAN provided: use empty subject DN
							subjectDn = "";
						}
					} else {
						// No SAN provided
						subjectAltName = null;

						if (customSubjectDn != null) {
							// Only DN provided: use custom DN with prefix/postfix
							subjectDn = applyPrefixPostfixToCN(customSubjectDn, prefix, postfix, i, j);
						} else {
							// Neither SAN nor DN provided: default behavior with CN
							subjectDn = "CN=" + endEntityName;
						}
					}

					// Generate certificates for this end entity (1 base + historyCount additional)
					for (int h = 0; h < certsPerEntity; ++h) {
						// Determine the key index for this certificate
						final int keyIndex = payloadIndex;

						if (keyPair == null || !singleKey) {
							// Try to load key from directory if loadKeysDir is specified
							if (!StringUtils.isBlank(loadKeysDir)) {
								keyPair = loadKeyPair(loadKeysDir, keyAlg, keySpec, i, keyIndex);
								if (keyPair == null) {
									throw new IllegalStateException("Could not load key pair from " + loadKeysDir + " for thread " + i + ", index " + keyIndex);
								}
							} else {
								// Generate new key
								try {
									keyPair = KeyTools.genKeys(keySpec, keyAlg);
								} catch (InvalidAlgorithmParameterException e) {
									throw new IllegalStateException("Could not generate key pairs.", e);
								}

								// Save key if saveKeysDir is specified
								if (!StringUtils.isBlank(saveKeysDir)) {
									saveKeyPair(keyPair, saveKeysDir, keyAlg, keySpec, i, keyIndex);
								}
							}
						}
						// Handle empty subject DN when only SAN is provided
						final X500Name userDN = StringUtils.isBlank(subjectDn) ? new X500Name("") : DnComponents.stringToBcX500Name(subjectDn);
						final PKCS10CertificationRequest pkcs10 = generateCertificateRequest(
								userDN, keyPair, keyAlg, subjectAltName);
						final StringWriter pemout = new StringWriter();
						JcaPEMWriter pm = new JcaPEMWriter(pemout);
						pm.writeObject(pkcs10);
						pm.close();
						final String p10pem = pemout.toString();
						JSONObject param = new JSONObject();
						param.put("certificate_request", p10pem);
						param.put("certificate_profile_name", certificateProfileName);
						param.put("end_entity_profile_name", endEntityProfileName);
						param.put("certificate_authority_name", caName);
						param.put("username", endEntityName);
						param.put("password", password);
						param.put("include_chain", "false");
						final StringWriter out = new StringWriter();
						param.writeJSONString(out);
						final String payload = out.toString();
						this.payloads[i][payloadIndex] = payload;
						this.subjectDns[i][payloadIndex] = subjectDn;
						payloadIndex++;
					}
				}
				if (i == counter) {
					log.info(((double) i) / ((double) numberOfThreads) * 100 + " % done.");
					counter += increment;
				}
			}
		} catch (IOException e) {
			throw new IllegalStateException("Could not generate CSR bucket.", e);
		}

	}

	/**
	 * Build the key filename with algorithm and keyspec information.
	 */
	private String buildKeyFilename(String directory, String keyAlg, String keySpec, int threadId, int keyIndex) {
		// Normalize the algorithm name for the filename
		String algName = keyAlg.toLowerCase().replace("_", "-");
		// For ML-DSA variants, keySpec is null, so we just use the algorithm name
		String specPart = (keySpec != null) ? "_" + keySpec.toLowerCase() : "";
		return directory + File.separator + "key_" + algName + specPart + "_" + threadId + "_" + keyIndex + ".pem";
	}

	/**
	 * Save a key pair to a PEM file in the specified directory.
	 */
	private void saveKeyPair(KeyPair keyPair, String directory, String keyAlg, String keySpec, int threadId, int keyIndex) {
		String filename = buildKeyFilename(directory, keyAlg, keySpec, threadId, keyIndex);
		try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filename))) {
			pemWriter.writeObject(keyPair.getPrivate());
			pemWriter.writeObject(keyPair.getPublic());
		} catch (IOException e) {
			throw new IllegalStateException("Failed to save key pair to " + filename, e);
		}
	}

	/**
	 * Load a key pair from a PEM file in the specified directory.
	 */
	private KeyPair loadKeyPair(String directory, String keyAlg, String keySpec, int threadId, int keyIndex) {
		String filename = buildKeyFilename(directory, keyAlg, keySpec, threadId, keyIndex);
		File keyFile = new File(filename);
		if (!keyFile.exists()) {
			log.error("Key file not found: " + filename);
			return null;
		}

		try (PEMParser pemParser = new PEMParser(new FileReader(filename))) {
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
			Object object = pemParser.readObject();

			if (object instanceof PEMKeyPair) {
				return converter.getKeyPair((PEMKeyPair) object);
			} else if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
				// Handle private key info - need to also read public key
				java.security.PrivateKey privateKey = converter.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) object);
				Object publicKeyObj = pemParser.readObject();
				if (publicKeyObj instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) {
					java.security.PublicKey publicKey = converter.getPublicKey((org.bouncycastle.asn1.x509.SubjectPublicKeyInfo) publicKeyObj);
					return new KeyPair(publicKey, privateKey);
				}
			}

			log.error("Unexpected key format in file: " + filename);
			return null;
		} catch (IOException e) {
			log.error("Failed to load key pair from " + filename + ": " + e.getMessage());
			return null;
		}
	}

	private static PKCS10CertificationRequest generateCertificateRequest(final X500Name userDN, final KeyPair keyPair, final String keyAlg, final String subjectAltName) throws IOException {
		try {
			final PublicKey publicKey = keyPair.getPublic();
			final String sigAlg;

			// Determine signature algorithm based on key algorithm
			if (AlgorithmConstants.KEYALGORITHM_RSA.equals(keyAlg)) {
				sigAlg = "SHA256WithRSA";
			} else if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(keyAlg) || AlgorithmConstants.KEYALGORITHM_EC.equals(keyAlg)) {
				sigAlg = "SHA256WithECDSA";
			} else if (AlgorithmConstants.KEYALGORITHM_MLDSA44.equals(keyAlg)) {
				sigAlg = "ML-DSA-44";
			} else if (AlgorithmConstants.KEYALGORITHM_MLDSA65.equals(keyAlg)) {
				sigAlg = "ML-DSA-65";
			} else if (AlgorithmConstants.KEYALGORITHM_MLDSA87.equals(keyAlg)) {
				sigAlg = "ML-DSA-87";
			} else {
				// Fall back to AlgorithmTools for automatic detection
				List<String> sigAlgs = AlgorithmTools.getSignatureAlgorithms(publicKey);
				if (sigAlgs.isEmpty()) {
					throw new IllegalStateException("Unable to determine signature algorithm for key type: " + publicKey.getClass().getName());
				}
				if (publicKey instanceof RSAPublicKey) {
					sigAlg = "SHA256WithRSA"; // Avoid SHA1WithRSA
				} else {
					sigAlg = sigAlgs.get(0);
				}
			}

			// Add SAN extension if provided
			ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
			if (!StringUtils.isBlank(subjectAltName)) {
				GeneralNames san = DnComponents.getGeneralNamesFromAltName(subjectAltName);
				extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, san);
			}

			DERSet attributes;
			if (!extensionsGenerator.isEmpty()) {
				final Extensions extensions = extensionsGenerator.generate();
				// Add the extension(s) to the PKCS#10 request as a pkcs_9_at_extensionRequest
				ASN1EncodableVector extensionattr = new ASN1EncodableVector();
				extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
				extensionattr.add(new DERSet(extensions));
				// Complete the Attribute section of the request, the set (Attributes) contains one sequence (Attribute)
				ASN1EncodableVector v = new ASN1EncodableVector();
				v.add(new DERSequence(extensionattr));
				attributes = new DERSet(v);
			} else {
				attributes = new DERSet();
			}

			return CertTools.genPKCS10CertificationRequest(sigAlg, userDN,
					publicKey, attributes, keyPair.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException("Unable to generate CSR.", e);
		}

	}

	private String applyPrefixPostfixToCN(final String subjectDn, final String prefix, final String postfix, final int threadId, final int certId) {
		// Parse the subject DN to find CN attribute
		String[] parts = subjectDn.split(",");
		StringBuilder result = new StringBuilder();

		for (int i = 0; i < parts.length; i++) {
			String part = parts[i].trim();
			if (part.toUpperCase().startsWith("CN=")) {
				// Extract the CN value
				String cnValue = part.substring(3).trim();
				// Apply prefix and postfix
				String modifiedCN = "CN=" + prefix + "_" + cnValue + "_" + threadId + "_" + certId + (StringUtils.isEmpty(postfix) ? "" : "_" + postfix);
				result.append(modifiedCN);
			} else {
				result.append(part);
			}

			if (i < parts.length - 1) {
				result.append(",");
			}
		}

		return result.toString();
	}

	private String applyPrefixPostfixToSAN(final String subjectAltName, final String prefix, final String postfix, final int threadId, final int certId) {
		// Parse the SAN to find dnsName attributes and apply prefix/postfix
		String[] parts = subjectAltName.split(",");
		StringBuilder result = new StringBuilder();

		for (int i = 0; i < parts.length; i++) {
			String part = parts[i].trim();
			if (part.toLowerCase().startsWith("dnsname=")) {
				// Extract the dnsName value
				String dnsValue = part.substring(8).trim();
				// Apply prefix and postfix to DNS name
				String modifiedDNS = "dnsName=" + prefix + "_" + dnsValue + "_" + threadId + "_" + certId + (StringUtils.isEmpty(postfix) ? "" : "_" + postfix);
				result.append(modifiedDNS);
			} else {
				// Keep other SAN types unchanged (ipAddress, email, etc.)
				result.append(part);
			}

			if (i < parts.length - 1) {
				result.append(",");
			}
		}

		return result.toString();
	}

	private String extractCNForErrorMessage(final String subjectDn) {
		// Extract CN from subject DN for error messages
		if (StringUtils.isBlank(subjectDn)) {
			return "";
		}

		String[] parts = subjectDn.split(",");
		for (String part : parts) {
			String trimmedPart = part.trim();
			if (trimmedPart.toUpperCase().startsWith("CN=")) {
				// Extract the CN value and return in the format ", CN=value"
				return ", " + trimmedPart;
			}
		}

		// No CN found, return empty string
		return "";
	}

	private void revokeCertificate(X509Certificate certificate, String issuerDn, String serialNumber, boolean backdateRevocation, int threadId, int iteration, String cnInfo, List<String> failures) {
		try {
			// Escape invalid URL characters
			issuerDn = escapeInvalidUrlCharacters(issuerDn);

			// Build revocation URL
			StringBuilder urlBuilder = new StringBuilder()
					.append("https://")
					.append(getHostname())
					.append(REVOKE_URL_PREFIX)
					.append(issuerDn)
					.append("/")
					.append(serialNumber)
					.append(REVOKE_URL_SUFFIX)
					.append("?reason=")
					.append(REVOCATION_REASON);

			// Only add date parameter if backdating is requested
			if (backdateRevocation) {
				// Use the certificate's notBefore date for backdated revocation
				OffsetDateTime date = certificate.getNotBefore().toInstant().atOffset(java.time.ZoneOffset.UTC).truncatedTo(ChronoUnit.SECONDS);
				String revocationDate = escapeInvalidUrlCharacters(date.toString());
				urlBuilder.append("&date=").append(revocationDate);
			}

			final String revokeUrl = urlBuilder.toString();

			// Create revocation request
			JSONObject param = new JSONObject();
			final StringWriter out = new StringWriter();
			param.writeJSONString(out);
			final String payload = out.toString();

			final HttpPut revokeRequest = new HttpPut(revokeUrl);
			revokeRequest.setEntity(new StringEntity(payload));

			try (CloseableHttpResponse revokeResponse = performRESTAPIRequest(getSslContext(), revokeRequest)) {
				final InputStream entityContent = revokeResponse.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
				int statusCode = revokeResponse.getStatusLine().getStatusCode();

				if (statusCode != 200 && statusCode != 201) {
					String msgRevokeFailed = "Thread ID: " + threadId + ", Iteration: " + iteration + cnInfo
							+ " - Revocation failed with code " + statusCode + ": " + responseString;
					getLogger().error(msgRevokeFailed);
					failures.add(msgRevokeFailed);
					synchronized (X509StressTestCommand.this) {
						totalFailedRevocations++;
					}
				} else {
					synchronized (X509StressTestCommand.this) {
						totalSuccessfulRevocations++;
					}
				}
			}
		} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
			String msgRevokeError = "Thread ID: " + threadId + ", Iteration: " + iteration + cnInfo
					+ " - Revocation request failed: " + e.getMessage();
			getLogger().error(msgRevokeError);
			failures.add(msgRevokeError);
			synchronized (X509StressTestCommand.this) {
				totalFailedRevocations++;
			}
		}
	}

	private String escapeInvalidUrlCharacters(final String urlElement) {
		return urlElement.replace(" ", "%20").replace("+", "%2b");
	}

	/**
	 * Save issued certificates to file
	 */
	private void saveCertificatesToFile(List<CertificateInfo> certificates, String filename) {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
			for (CertificateInfo cert : certificates) {
				writer.write(cert.toString());
				writer.newLine();
			}
			log.info("Saved " + certificates.size() + " certificate(s) to file: " + filename);
		} catch (IOException e) {
			log.error("Failed to save certificates to file " + filename + ": " + e.getMessage());
		}
	}

	/**
	 * Load certificates from file
	 */
	private List<CertificateInfo> loadCertificatesFromFile(String filename) {
		List<CertificateInfo> certificates = new ArrayList<>();
		try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
			String line;
			while ((line = reader.readLine()) != null) {
				line = line.trim();
				if (!line.isEmpty() && !line.startsWith("#")) {
					CertificateInfo cert = CertificateInfo.fromString(line);
					if (cert != null) {
						certificates.add(cert);
					} else {
						log.warn("Skipping invalid line in " + filename + ": " + line);
					}
				}
			}
			log.info("Loaded " + certificates.size() + " certificate(s) from file: " + filename);
		} catch (IOException e) {
			log.error("Failed to load certificates from file " + filename + ": " + e.getMessage());
		}
		return certificates;
	}

	/**
	 * Write issuance test results to CSV file
	 */
	private void writeIssuanceResultsToCsv(String filename, long totalCerts, long successfulIssuances, long issuanceFailures,
			long successfulRevocations, long revocationFailures, long duration, boolean includeRevocation) throws IOException {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
			// Write header
			if (includeRevocation) {
				writer.write("Test Duration (s),Total Certificates,Successful Issuances,Failed Issuances,Throughput (certs/s),Successful Revocations,Failed Revocations,Timestamp");
			} else {
				writer.write("Test Duration (s),Total Certificates,Successful Issuances,Failed Issuances,Throughput (certs/s),Timestamp");
			}
			writer.newLine();

			// Calculate throughput
			double executionTime = duration / 1000.0;
			double throughput = executionTime > 0 ? successfulIssuances / executionTime : 0;

			// Write data row
			String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
			if (includeRevocation) {
				writer.write(String.format("%.2f,%d,%d,%d,%.2f,%d,%d,%s",
						executionTime, totalCerts, successfulIssuances, issuanceFailures, throughput,
						successfulRevocations, revocationFailures, timestamp));
			} else {
				writer.write(String.format("%.2f,%d,%d,%d,%.2f,%s",
						executionTime, totalCerts, successfulIssuances, issuanceFailures, throughput, timestamp));
			}
			writer.newLine();
		}
	}

	/**
	 * Write issuance test results to Markdown file
	 */
	private void writeIssuanceResultsToMarkdown(String filename, long totalCerts, long successfulIssuances, long issuanceFailures,
			long successfulRevocations, long revocationFailures, long duration, boolean includeRevocation) throws IOException {
		double executionTime = duration / 1000.0;
		double throughput = executionTime > 0 ? successfulIssuances / executionTime : 0;
		String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
			writer.write("# X509 Stress Test Results");
			writer.newLine();
			writer.newLine();
			writer.write("**Generated:** " + timestamp);
			writer.newLine();
			writer.newLine();

			// Test Configuration section
			writer.write("## Test Configuration");
			writer.newLine();
			writer.newLine();
			writer.write("| Metric | Value |");
			writer.newLine();
			writer.write("|--------|-------|");
			writer.newLine();
			writer.write(String.format("| Test Duration | %.2f seconds |", executionTime));
			writer.newLine();
			writer.newLine();

			// Issuance Metrics table
			writer.write("## Issuance Metrics");
			writer.newLine();
			writer.newLine();
			writer.write("| Metric | Value |");
			writer.newLine();
			writer.write("|--------|-------|");
			writer.newLine();
			writer.write(String.format("| Total Certificates | %,d |", totalCerts));
			writer.newLine();
			writer.write(String.format("| Successful Issuances | %,d |", successfulIssuances));
			writer.newLine();
			writer.write(String.format("| Failed Issuances | %,d |", issuanceFailures));
			writer.newLine();
			writer.write(String.format("| Throughput | %.2f certs/s |", throughput));
			writer.newLine();
			writer.newLine();

			// Revocation Metrics table (if revocation was performed)
			if (includeRevocation) {
				writer.write("## Revocation Metrics");
				writer.newLine();
				writer.newLine();
				writer.write("| Metric | Value |");
				writer.newLine();
				writer.write("|--------|-------|");
				writer.newLine();
				writer.write(String.format("| Successful Revocations | %,d |", successfulRevocations));
				writer.newLine();
				writer.write(String.format("| Failed Revocations | %,d |", revocationFailures));
				writer.newLine();
				writer.newLine();
			}
		}
	}

	/**
	 * Write bulk revocation test results to CSV file
	 */
	private void writeRevocationResultsToCsv(String filename, long totalCerts, long successfulRevocations,
			long revocationFailures, long duration) throws IOException {
		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
			// Write header
			writer.write("Test Duration (s),Total Certificates,Successful Revocations,Failed Revocations,Throughput (certs/s),Timestamp");
			writer.newLine();

			// Calculate throughput
			double executionTime = duration / 1000.0;
			double throughput = executionTime > 0 ? successfulRevocations / executionTime : 0;

			// Write data row
			String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
			writer.write(String.format("%.2f,%d,%d,%d,%.2f,%s",
					executionTime, totalCerts, successfulRevocations, revocationFailures, throughput, timestamp));
			writer.newLine();
		}
	}

	/**
	 * Write bulk revocation test results to Markdown file
	 */
	private void writeRevocationResultsToMarkdown(String filename, long totalCerts, long successfulRevocations,
			long revocationFailures, long duration) throws IOException {
		double executionTime = duration / 1000.0;
		double throughput = executionTime > 0 ? successfulRevocations / executionTime : 0;
		String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());

		try (BufferedWriter writer = new BufferedWriter(new FileWriter(filename))) {
			writer.write("# X509 Bulk Revocation Test Results");
			writer.newLine();
			writer.newLine();
			writer.write("**Generated:** " + timestamp);
			writer.newLine();
			writer.newLine();

			// Test Configuration section
			writer.write("## Test Configuration");
			writer.newLine();
			writer.newLine();
			writer.write("| Metric | Value |");
			writer.newLine();
			writer.write("|--------|-------|");
			writer.newLine();
			writer.write(String.format("| Test Duration | %.2f seconds |", executionTime));
			writer.newLine();
			writer.newLine();

			// Revocation Metrics table
			writer.write("## Revocation Metrics");
			writer.newLine();
			writer.newLine();
			writer.write("| Metric | Value |");
			writer.newLine();
			writer.write("|--------|-------|");
			writer.newLine();
			writer.write(String.format("| Total Certificates | %,d |", totalCerts));
			writer.newLine();
			writer.write(String.format("| Successful Revocations | %,d |", successfulRevocations));
			writer.newLine();
			writer.write(String.format("| Failed Revocations | %,d |", revocationFailures));
			writer.newLine();
			writer.write(String.format("| Throughput | %.2f certs/s |", throughput));
			writer.newLine();
			writer.newLine();
		}
	}

	/**
	 * Perform bulk revocation of certificates from file
	 */
	private CommandResult performBulkRevocation(String filename, boolean backdateRevocation, int numberOfThreads,
			String outputFormat, String outputFile, int progressInterval) {
		log.info("Starting bulk revocation from file: " + filename);

		// Load certificates from file
		List<CertificateInfo> certificates = loadCertificatesFromFile(filename);
		if (certificates.isEmpty()) {
			log.error("No certificates found in file: " + filename);
			return CommandResult.CLI_FAILURE;
		}

		log.info("Loaded " + certificates.size() + " certificate(s) for revocation");
		log.info("Using " + numberOfThreads + " thread(s) for parallel revocation");

		// Split certificates across threads
		int certsPerThread = (int) Math.ceil((double) certificates.size() / numberOfThreads);
		final long expectedTotalRevocations = certificates.size();

		// Reset counters
		totalIssuanceAttempts = 0;
		totalSuccessfulIssuances = 0;
		totalFailedIssuances = 0;
		totalSuccessfulRevocations = 0;
		totalFailedRevocations = 0;
		stopProgressTracking = false;

		// Start progress tracking thread if enabled
		Thread progressThread = null;
		if (progressInterval > 0) {
			progressThread = new Thread(() -> {
				long lastRevoked = 0;
				long lastTime = System.currentTimeMillis();

				while (!stopProgressTracking) {
					try {
						Thread.sleep(progressInterval * 1000L);

						if (stopProgressTracking) {
							break;
						}

						long currentTime = System.currentTimeMillis();
						long currentRevoked = totalSuccessfulRevocations + totalFailedRevocations;
						long intervalRevoked = currentRevoked - lastRevoked;
						double intervalSeconds = (currentTime - lastTime) / 1000.0;
						double certsPerSec = intervalSeconds > 0 ? intervalRevoked / intervalSeconds : 0;

						System.out.println(String.format("Progress: %d/%d certs revoked (%d successful, %d failed) - %.2f certs/s",
								currentRevoked, expectedTotalRevocations, totalSuccessfulRevocations, totalFailedRevocations, certsPerSec));

						lastRevoked = currentRevoked;
						lastTime = currentTime;
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						break;
					}
				}
			});
			progressThread.setDaemon(true);
			progressThread.start();
		}

		log.info("\nWeapons free. Fire for effect (revocation only).");
		long startTime = System.currentTimeMillis();

		List<CompletableFuture<List<String>>> futures = new ArrayList<>();
		for (int threadNumber = 0; threadNumber < numberOfThreads; threadNumber++) {
			final int startIdx = threadNumber * certsPerThread;
			final int endIdx = Math.min(startIdx + certsPerThread, certificates.size());

			if (startIdx >= certificates.size()) {
				break; // No more certificates to process
			}

			final List<CertificateInfo> threadCerts = certificates.subList(startIdx, endIdx);
			final int threadId = threadNumber;

			futures.add(CompletableFuture.supplyAsync(() -> {
				List<String> revocationFailures = new ArrayList<>();

				for (int i = 0; i < threadCerts.size(); i++) {
					CertificateInfo cert = threadCerts.get(i);
					String issuerDnEscaped = escapeInvalidUrlCharacters(cert.issuerDn);

					// Build revocation URL
					StringBuilder urlBuilder = new StringBuilder()
						.append("https://").append(getHostname())
						.append("/ejbca/ejbca-rest-api/v1/certificate/")
						.append(issuerDnEscaped).append("/")
						.append(cert.serialNumber).append("/revoke")
						.append("?reason=UNSPECIFIED");

					// Add date parameter only if backdating is requested
					if (backdateRevocation) {
						// For bulk revocation, we don't have the certificate's notBefore date
						// So we'll use current time if backdating is requested (user should handle this carefully)
						OffsetDateTime date = OffsetDateTime.now().truncatedTo(ChronoUnit.SECONDS);
						String dateStr = escapeInvalidUrlCharacters(date.toString());
						urlBuilder.append("&date=").append(dateStr);
					}

					String restUrl = urlBuilder.toString();

					try {
						JSONObject param = new JSONObject();
						final StringWriter out = new StringWriter();
						param.writeJSONString(out);
						final String payload = out.toString();

						final HttpPut request = new HttpPut(restUrl);
						request.setEntity(new StringEntity(payload));

						try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
							final InputStream entityContent = response.getEntity().getContent();
							String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);

							int statusCode = response.getStatusLine().getStatusCode();
							if (statusCode != 200 && statusCode != 201) {
								String errorMsg = "Thread ID: " + threadId + ", Index: " + i +
									", SN=" + cert.serialNumber + " - Revocation failed with code " +
									statusCode + ": " + responseString;
								revocationFailures.add(errorMsg);
								log.error(errorMsg);
								synchronized (X509StressTestCommand.this) {
									totalFailedRevocations++;
								}
							} else {
								synchronized (X509StressTestCommand.this) {
									totalSuccessfulRevocations++;
								}
							}
						}
					} catch (Exception e) {
						String errorMsg = "Thread ID: " + threadId + ", Index: " + i +
							", SN=" + cert.serialNumber + " - Revocation failed with exception: " + e.getMessage();
						revocationFailures.add(errorMsg);
						log.error(errorMsg);
						synchronized (X509StressTestCommand.this) {
							totalFailedRevocations++;
						}
					}
				}

				return revocationFailures;
			}));
		}

		// Wait for all threads to complete
		CompletableFuture<Void> allFutures = CompletableFuture.allOf(futures.toArray(CompletableFuture<?>[]::new));
		List<String> allRevocationFailures = new ArrayList<>();

		allFutures.thenRun(() -> {
			for (CompletableFuture<List<String>> completedFuture : futures) {
				try {
					List<String> failures = completedFuture.get();
					allRevocationFailures.addAll(failures);
				} catch (ExecutionException | InterruptedException e) {
					log.error("Future could not execute.", e);
				}
			}
		});

		allFutures.join();
		long endTime = System.currentTimeMillis();

		// Stop progress tracking
		stopProgressTracking = true;

		log.info("Fire mission complete. Weapons hold.\n");

		// Print failures if any
		if (!allRevocationFailures.isEmpty()) {
			log.info("The following certificates failed to revoke:");
			for (String error : allRevocationFailures) {
				log.info(error);
			}
		}

		// Print statistics
		long totalCerts = certificates.size();
		long successfulRevocations = totalCerts - allRevocationFailures.size();
		long duration = endTime - startTime;
		double executionTime = duration / 1000.0;

		log.info("Total execution time: " + executionTime + " seconds.");
		if (successfulRevocations > 0) {
			double averageTime = executionTime / successfulRevocations;
			log.info("Average revocation time: " + averageTime + " seconds.");
			log.info("Throughput: " + (1 / averageTime) + " certificates revoked per second.");
		}
		log.info(successfulRevocations + " certificates were successfully revoked, with " +
			allRevocationFailures.size() + " revocation failures.");

		// Write results to file if requested
		if (outputFormat.equals("csv")) {
			try {
				writeRevocationResultsToCsv(outputFile, totalCerts, successfulRevocations,
						allRevocationFailures.size(), duration);
				log.info("Results saved to " + outputFile);
			} catch (IOException e) {
				log.error("Failed to write CSV results to file: " + e.getMessage());
				return CommandResult.CLI_FAILURE;
			}
		} else if (outputFormat.equals("markdown")) {
			try {
				writeRevocationResultsToMarkdown(outputFile, totalCerts, successfulRevocations,
						allRevocationFailures.size(), duration);
				log.info("Results saved to " + outputFile);
			} catch (IOException e) {
				log.error("Failed to write Markdown results to file: " + e.getMessage());
				return CommandResult.CLI_FAILURE;
			}
		}

		return CommandResult.SUCCESS;
	}


}
