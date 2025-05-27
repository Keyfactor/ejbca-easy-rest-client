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

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * This class provides the ability to use ERCE to perform a stress test against
 * EJBCA.
 */

public class X509StressTestCommand extends ErceCommandBase {

	private static final Logger log = Logger.getLogger(X509StressTestCommand.class);

	private static final String STRESS_TEST_PREFIX_DEFAULT = "ErceStressTest_";
	private static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll";

	private static final String CA_ARG = "--ca";
	private static final String CERTIFICATE_PROFILE_ARG = "--certificateprofile";
	private static final String END_ENTITY_PROFILE_ARG = "--endentityprofile";
	private static final String THREADS_ARG = "--threads";
	private static final String CERTS_PER_THREAD_ARG = "--certs";
	private static final String REUSE_KEY_ARG = "--singlekey";
	private static final String PREFIX_ARG = "--prefix";
	private static final String POSTFIX_ARG = "--postfix";

	private String[][] payloads;

	{
		registerParameter(new Parameter(CA_ARG, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Name of the Certificate Authority to test against."));
		registerParameter(new Parameter(END_ENTITY_PROFILE_ARG, "End Entity Profile Name", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "End Entity Profile Name"));
		registerParameter(new Parameter(CERTIFICATE_PROFILE_ARG, "Certificate Profile Name", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Certificate Profile Name"));
		registerParameter(new Parameter(THREADS_ARG, "Numeric Value", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Number of threads."));
		registerParameter(new Parameter(CERTS_PER_THREAD_ARG, "Numeric Value", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Number CSRs to generate per thread."));
		registerParameter(new Parameter(REUSE_KEY_ARG, "", MandatoryMode.OPTIONAL,
				StandaloneMode.FORBID, ParameterMode.FLAG, "Set this flag to use the same key for all CSRs. Be aware that unique public keys must be disabled on the CA."));
		registerParameter(new Parameter(PREFIX_ARG, "prefix", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Optional prefix value for usernames and CNs. Default is '" + STRESS_TEST_PREFIX_DEFAULT + "'"));
		registerParameter(new Parameter(POSTFIX_ARG, "postfix", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Optional postfix value for usernames and CNs. Default is blank."));

	}

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
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

		final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(COMMAND_URL)
				.toString();

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
		
		generatePayloads(numberOfThreads, requestPerThread, caName, certificateProfileName, endEntityProfileName, singleKey, prefix, postfix);
		log.info("All CSR payloads transferred to caches..\n\nPreparing orbital bombardment in....");
		try {
			for (int i = 3; i > 0; --i) {
				log.info(i + "...");
				Thread.sleep(500);
			}
		} catch (InterruptedException e) {
			throw new IllegalStateException(e);
		}
		
		log.info("\nWeapons free. Fire for effect.");
		
		long startTime = System.currentTimeMillis();
		List<CompletableFuture<List<String>>> futures = new ArrayList<>();
		for (int threadNumber = 0; threadNumber < numberOfThreads; ++threadNumber) {
			final int row = threadNumber;
			futures.add(CompletableFuture.supplyAsync(() -> {
				
				List<String> failures = new ArrayList<>();
				for (int i = 0; i < requestPerThread; ++i) {
					String payload = payloads[row][i];
					final HttpPost request = new HttpPost(restUrl);
					try {
						request.setEntity(new StringEntity(payload));
						// connect to EJBCA and send the CSR and get an issued certificate back
						try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request)) {
							final InputStream entityContent = response.getEntity().getContent();
							String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);
							switch (response.getStatusLine().getStatusCode()) {
							case 404:
								String msg404 =  "Thread ID: " + row + ", Iteration: " + i + " - Return code was: 404: " + responseString;
								getLogger().error(msg404);
								failures.add(msg404);
								break;
							case 200:
							case 201:
								// Do nothing.
								break;
							default:
								String msgOthers = "Thread ID: " + row + ", Iteration: " + i + " - Return code was: " + response.getStatusLine().getStatusCode() + ": "
										+ responseString;
								getLogger().error(msgOthers);
								failures.add(msgOthers);
								break;
							}
						} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException
								| KeyStoreException e) {
							getLogger().error("Could not perform request: " + e.getMessage());
						}
					} catch (IOException e) {
						getLogger().error("Could not perform request: " + e.getMessage());
					}
				}
				return failures;
			}));

		}
		CompletableFuture<Void> allFutures = CompletableFuture.allOf(futures.toArray(CompletableFuture<?>[]::new));
		List<String> results = new ArrayList<>();
		allFutures.thenRun(() -> {
			for (CompletableFuture<List<String>> completedFuture : futures) {
				try {
					results.addAll(completedFuture.get());
				} catch (ExecutionException | InterruptedException e) {
					log.error("Future could not execute.", e);
				}
			}
		});
		
		allFutures.join();
		long endTime = System.currentTimeMillis();
		log.info("Fire mission complete. Weapons hold.\n");

		if(!results.isEmpty()) {
			log.info("The following threads did not return a certificate:");
			for(String error : results) {
				log.info(error);
			}
			
		}
		
		long totalCerts = numberOfThreads*requestPerThread;
		long success = totalCerts-results.size();
		double executionTime =  (endTime - startTime)/1000;
		log.info("Total execution time: " + executionTime + " seconds.");
		if(success > 0) {
			double averageTime = executionTime / success;
			log.info("Average issuance time: " + averageTime + " seconds.");
			log.info("Throughput: " + 1 / averageTime + " certificates issued per second.");
		}
		log.info((success) + " certificates were successfully issued, with " + results.size() + " failures.");
		

		return CommandResult.SUCCESS;
	}

	@Override
	public String getFullHelpText() {
		StringBuilder sb = new StringBuilder();
		sb.append(getCommandDescription() + "\n\n");
		sb.append(
				"This command will spin up an n number of threads, which will submit an x number of pre-genereated CSRs each against the given CA.\n");
		sb.append("For simplicity, the keys generated for each CSR will be set to use Elliptic Curve P256\n\n");
		sb.append(
				"To allow for easy cleaning of the database afterwards, all end entities will have their usernames prefixed with "
						+ STRESS_TEST_PREFIX_DEFAULT + "\n");
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
			final String certificateProfileName, final String endEntityProfileName, final boolean singleKey, final String prefix, final String postfix) {
		log.info("Will submit a total of " + requestPerThread * numberOfThreads + " CSRs, using " + numberOfThreads
				+ " threads.");
		log.info("Pre generating CSR payloads...");
		final String password = "foo123";
		this.payloads = new String[numberOfThreads][requestPerThread];
		final int increment = numberOfThreads / 10;
		int counter = 0;
		KeyPair keyPair = null;	
		try {
			for (int i = 0; i < numberOfThreads; ++i) {
				for (int j = 0; j < requestPerThread; ++j) {
					final String endEntityName = prefix + "_" + i + "_" + j + (StringUtils.isEmpty(postfix) ? "" : "_" + postfix);
					final String subjectDn = "CN=" + endEntityName;					
					if (keyPair == null || !singleKey) {
						try {
							keyPair = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
						} catch (InvalidAlgorithmParameterException e) {
							throw new IllegalStateException("Could not generate key pairs.", e);
						}
					}
					final PKCS10CertificationRequest pkcs10 = generateCertificateRequest(
							DnComponents.stringToBcX500Name(subjectDn), keyPair);
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
					this.payloads[i][j] = payload;
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

	private static PKCS10CertificationRequest generateCertificateRequest(final X500Name userDN, final KeyPair keyPair) throws IOException {
		try {
			return CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, userDN,
					keyPair.getPublic(), null, keyPair.getPrivate(), BouncyCastleProvider.PROVIDER_NAME);
		} catch (OperatorCreationException e) {
			throw new IllegalStateException("Unable to generate CSR:.", e);
		}

	}


}
