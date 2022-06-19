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
package com.keyfactor.ejbca.client.enroll;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.ejbca.util.AlgorithmTools;
import com.keyfactor.ejbca.util.CertTools;
import com.keyfactor.ejbca.util.KeyTools;

/**
 * A CLI command which invokes the "pkcs10enroll" REST command
 *
 */
public class EnrollGenKeysCommand extends EnrollCommandBase {

	private static final String KEYALG_ARG = "--keyalg";
	private static final String KEYSPEC_ARG = "--keyspec";

	private static final Set<String> RSA_KEY_SIZES = new LinkedHashSet<>(
			Arrays.asList("1024", "1536", "2048", "3072", "4096", "6144", "8192"));
	private static final Set<String> EC_CURVES = AlgorithmTools.preProcessCurveNames().keySet();

	private PublicKey publicKey;
	private PrivateKey privateKey;

	{
		registerParameter(new Parameter(KEYALG_ARG, "cipher", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Cipher must be one of [ " + KeyTools.KEYALGORITHM_RSA + ", " + KeyTools.KEYALGORITHM_EC + ", "
						+ KeyTools.KEYALGORITHM_ED25519 + ", " + KeyTools.KEYALGORITHM_ED448 + "]"));
		StringBuilder ecCurvesFormatted = new StringBuilder();
		ecCurvesFormatted.append("[");
		for (String curveName : EC_CURVES) {
			ecCurvesFormatted.append(" ").append(curveName).append(",");
		}
		ecCurvesFormatted.deleteCharAt(ecCurvesFormatted.lastIndexOf(","));
		ecCurvesFormatted.append(" ]");
		registerParameter(new Parameter(KEYSPEC_ARG, "Key Specification", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Key Specification.\n If cipher was RSA, must be one of [ 1024, 1536, 2048, 3072, 4096, 6144, 8192 ].\n If cipher was EC, must be one of "
						+ ecCurvesFormatted + ". Should be omitted for Ed25519 and Ed448."));
	}

	private static final Logger log = Logger.getLogger(EnrollGenKeysCommand.class);

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		Security.addProvider(new BouncyCastleProvider());
		final String keySpec = parameters.get(KEYSPEC_ARG);
		String keyAlg = parameters.get(KEYALG_ARG);

		switch (keyAlg.toUpperCase()) {
		case "RSA":
			keyAlg = KeyTools.KEYALGORITHM_RSA;
			if (!RSA_KEY_SIZES.contains(keySpec)) {
				log.error("Key size " + keySpec + " is invalid for RSA Keys.");
				return CommandResult.CLI_FAILURE;
			}
			break;
		case "EC":
		case "ECDSA":
			keyAlg = KeyTools.KEYALGORITHM_EC;
			if (!EC_CURVES.contains(keySpec)) {
				log.error(keySpec + " is not a known EC curve.");
				return CommandResult.CLI_FAILURE;
			}
			break;
		case "ED25519":
			keyAlg = KeyTools.KEYALGORITHM_ED25519;
			break;
		case "ED448":
			keyAlg = KeyTools.KEYALGORITHM_ED448;
			break;
		default:
			log.error("Key Algorithm " + keyAlg + " was unknown.");
			return CommandResult.CLI_FAILURE;
		}
		KeyPair keyPair;
		try {
			keyPair = KeyTools.genKeys(keySpec, keyAlg);
		} catch (InvalidAlgorithmParameterException e) {
			log.error("Caught invalid parameter exception: " + e.getMessage());
			return CommandResult.CLI_FAILURE;
		}
		this.privateKey = keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
		CommandResult result = super.execute(parameters);
		// Build a PKCS#12 that we can write to disk
		byte[] encodedKeystore;
		try {
			KeyStore pkcs12 = KeyTools.createP12(getUsername(), this.privateKey, getCertificate(), getPassword());
			this.privateKey = null;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			pkcs12.store(baos, getPassword().toCharArray());
			encodedKeystore = baos.toByteArray();
		} catch (CertificateException | NoSuchAlgorithmException | InvalidKeySpecException | KeyStoreException
				| IOException e) {
			log.error("Could not generate PKCS#12 keystore.", e);
			return CommandResult.FUNCTIONAL_FAILURE;
		}
		
		try {           
			File p12File = new File(getDestination(), getUsername()+".p12");
            FileOutputStream fos = new FileOutputStream(p12File);
            fos.write(encodedKeystore);
            fos.close();
            log.info("PKCS#12 written to '" + p12File.getAbsolutePath() + "'");
        } catch (FileNotFoundException e) {
            log.error("Destination directory not found: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IOException e) {
            throw new IllegalStateException("Could not write to file for unknown reason", e);
        } 

		return result;
	}

	@Override
	public String getMainCommand() {
		return "genkeys";
	}

	@Override
	public String getCommandDescription() {
		return "Command for enrolling to EJBCA, creating a keypair into the directory specified by the "
				+ DESTINATION_ARG + " flag (or the PWD if none specified)";
	}

	@Override
	public String getFullHelpText() {
		return getCommandDescription();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

	@Override
	protected PKCS10CertificationRequest getCsr(final X500Name userdn, final String subjectAltName) throws IOException {
		return CertTools.generateCertificateRequest(userdn, subjectAltName, publicKey, privateKey);
	}

}
