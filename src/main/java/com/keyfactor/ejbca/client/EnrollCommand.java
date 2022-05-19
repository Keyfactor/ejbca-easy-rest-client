/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.ejbca.client;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.keyfactor.ejbca.util.Base64;
import com.keyfactor.ejbca.util.CertTools;
import com.keyfactor.ejbca.util.KeyTools;

/**
 * A CLI command which invokes the "pkcs10enroll" REST command
 *
 */
public class EnrollCommand extends ErceCommandBase {

	private static final String COMMAND_URL = "/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll";

	private static final String PUBKEY_ARGS = "--pubkey";
	private static final String PRIVKEY_ARGS = "--privkey";
	private static final String SDN_ARG = "--subjectdn";
	private static final String SAN_ARG = "--subjectaltname";
	private static final String CERTIFICATE_PROFILE_ARGS = "--certificateprofile";
	private static final String END_ENTITY_PROFILE_ARGS = "--endentityprofile";
	private static final String CA_ARG = "--ca";
	private static final String USERNAME_ARGS = "--username";
	private static final String USERPASS_ARGS = "--password";
	private static final String DESTINATION_ARG = "--destination";

	{

		registerParameter(new Parameter(PUBKEY_ARGS, "Public Key File", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Complete path to the public key to sign"));
		registerParameter(
				new Parameter(PRIVKEY_ARGS, "Private Key file", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
						ParameterMode.ARGUMENT, "Complete path to the private key associated with the public key."));
		registerParameter(new Parameter(CA_ARG, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Certificate Authority name"));
		registerParameter(new Parameter(END_ENTITY_PROFILE_ARGS, "End Entity Profile Name", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "End Entity Profile Name"));
		registerParameter(new Parameter(CERTIFICATE_PROFILE_ARGS, "Certificate Profile Name", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Certificate Profile Name"));
		registerParameter(new Parameter(SDN_ARG, "Subject DN", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Requested Subject DN of the enrolled user."));
		registerParameter(new Parameter(SAN_ARG, "Subject Alt Name", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Requested Subject Alternative name of the enrolled user."));
		registerParameter(new Parameter(USERNAME_ARGS, "Username", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Username for the end entity"));
		registerParameter(new Parameter(USERPASS_ARGS, "Enrollment Password", MandatoryMode.MANDATORY,
				StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Enrollment Password for the enrolled end entity."));
		registerParameter(new Parameter(DESTINATION_ARG, "directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT, "Destination directory. Optional, pwd will be used if left out."));
	}

	private static final Logger log = Logger.getLogger(EnrollCommand.class);

	public static void main(String[] args) {
		Security.addProvider(new BouncyCastleProvider());
		EnrollCommand enrollCommand = new EnrollCommand();
		enrollCommand.execute(args);
	}

	@SuppressWarnings("unchecked")
	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		final String pubkeyFilename = parameters.get(PUBKEY_ARGS);
		final String privkeyFilename = parameters.get(PRIVKEY_ARGS);
		final String subjectAltName = parameters.get(SAN_ARG);
		final String endEntityProfileName = parameters.get(CERTIFICATE_PROFILE_ARGS);
		final String certificateProfileName = parameters.get(END_ENTITY_PROFILE_ARGS);
		final String caName = parameters.get(CA_ARG);
		final String subjectDn = parameters.get(SDN_ARG);
		final String username = parameters.get(USERNAME_ARGS);
		final String password = parameters.get(USERPASS_ARGS);

		File destination;
		if (parameters.containsKey(DESTINATION_ARG)) {
			final String destinationDirName = parameters.get(DESTINATION_ARG);
			destination = new File(destinationDirName);
			if (!destination.isDirectory() || !destination.canWrite()) {
				log.error("Directory " + destinationDirName + " was not a directory, or could not be written to.");
				return CommandResult.CLI_FAILURE;
			}
		} else {
			destination = new File(System.getProperty("user.dir"));
		}

		try {
			PublicKey publicKey = readPublicKey(pubkeyFilename);
			final PrivateKey privateKey = readPrivateKey(privkeyFilename);

			X500Name userDn = new X500Name(subjectDn);

			PKCS10CertificationRequest pkcs10 = CertTools.generateCertificateRequest(userDn, subjectAltName, publicKey,
					privateKey);

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
			param.put("username", username);
			param.put("password", password);
			param.put("include_chain", "false");
			final StringWriter out = new StringWriter();
			param.writeJSONString(out);
			final String payload = out.toString();

			final String restUrl = new StringBuilder().append("https://").append(getHostname()).append(getCommandUrl())
					.toString();
			final HttpPost request = new HttpPost(restUrl);
			// connect to EJBCA and send the CSR and get an issued certificate back
			try (CloseableHttpResponse response = performRESTAPIRequest(getSslContext(), request, payload)) {
				final InputStream entityContent = response.getEntity().getContent();
				String responseString = IOUtils.toString(entityContent, StandardCharsets.UTF_8);

				switch (response.getStatusLine().getStatusCode()) {
				case 404:
					log.error("Return code was: 404: " + responseString);
					break;
				case 200:
				case 201:
					log.info("End entity with username " + username + " has succesfully been enrolled.");
					final JSONParser jsonParser = new JSONParser();
					final JSONObject actualJsonObject = (JSONObject) jsonParser.parse(responseString);
					final String base64cert = (String) actualJsonObject.get("certificate");
					byte[] certBytes = Base64.decode(base64cert.getBytes());
					X509Certificate certificate = CertTools.getCertfromByteArray(certBytes);
					byte[] pembytes = CertTools.getPemFromCertificate(certificate);
					File certificateFile = new File(destination, username + ".pem");
					// Write the resulting cert to file
					try {
						FileOutputStream fos = new FileOutputStream(certificateFile);
						fos.write(pembytes);
						fos.close();
					} catch (IOException e) {
						log.error("Could not write to certificate file " + certificateFile + ". " + e.getMessage());
						return CommandResult.FUNCTIONAL_FAILURE;
					}
					log.info("PEM certificate written to file '" + certificateFile + "'");
					break;
				default:
					log.error("Return code was: " + response.getStatusLine().getStatusCode() + ": " + responseString);
					break;
				}
				return CommandResult.SUCCESS;

			} catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException
					| ParseException | CertificateParsingException e) {
				log.error("Could not perform request: " + e.getMessage());
				return CommandResult.FUNCTIONAL_FAILURE;
			}
		} catch (IOException e) {
			throw new IllegalStateException("Unknown IOException was caught.", e);
		}
	}

	protected String getCommandUrl() {
		return COMMAND_URL;
	}

	private PublicKey readPublicKey(final String filename) throws IOException {
		FileReader keyReader = new FileReader(new File(filename));
		try (PemReader pemReader = new PemReader(keyReader)) {
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			return KeyTools.getPublicKeyFromBytes(content);
		}
	}

	private PrivateKey readPrivateKey(final String filename) throws IOException {
		try (FileReader keyReader = new FileReader(new File(filename))) {

			PEMParser pemParser = new PEMParser(keyReader);
			Object pemObject = pemParser.readObject();
			PrivateKeyInfo privateKeyInfo;
			if (pemObject instanceof PEMKeyPair) {
				privateKeyInfo = ((PEMKeyPair) pemObject).getPrivateKeyInfo();
			} else {
				privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
			}
			JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
			return converter.getPrivateKey(privateKeyInfo);
		}
	}

	@Override
	public String getMainCommand() {
		return "enroll";
	}

	@Override
	public String getCommandDescription() {
		return "Command for enrolling to EJBCA.";
	}

	@Override
	public String getFullHelpText() {
		return "Command for enrolling to EJBCA. Can be used to enroll using a supplied public and private key. Example usage: --authkeystore=/Users/foo/superadmin.p12 --authkeystorepass=foo123 --pubkey=/Users/foo/public.pem --privkey=/Users/foo/key.pem --endentityprofile=simple --certificateprofile=simple --ca=foo --subjectaltname=\"\"  --hostname=localhost:8443 --destination=/Users/foo/ --subjectdn=\"CN= clitest13\" --username=clitest13 --password=foo123";
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

}
