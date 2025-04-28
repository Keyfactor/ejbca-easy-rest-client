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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyStoreCipher;
import com.keyfactor.util.keys.KeyTools;

/**
 * A CLI command which invokes the "pkcs10enroll" REST command
 *
 */
public class EnrollGenKeysCommand extends EnrollCommandBase {

	private static final String KEYALG_ARG = "--keyalg";
	private static final String KEYSPEC_ARG = "--keyspec";

	private static final Set<String> RSA_KEY_SIZES = new LinkedHashSet<>(
			Arrays.asList("1024", "1536", "2048", "3072", "4096", "6144", "8192"));
	private static final Set<String> EC_CURVES = AlgorithmTools.getNamedEcCurvesMap().keySet();

	private PublicKey publicKey;
	private PrivateKey privateKey;

	{
		registerParameter(new Parameter(KEYALG_ARG, "cipher", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
				ParameterMode.ARGUMENT,
				"Cipher must be one of [ " 	+ AlgorithmConstants.KEYALGORITHM_RSA + ", " 
											+ AlgorithmConstants.KEYALGORITHM_EC + ", "
											+ AlgorithmConstants.KEYALGORITHM_ED25519 + ", "
											+ AlgorithmConstants.KEYALGORITHM_ED448 + ", "
											+ AlgorithmConstants.KEYALGORITHM_MLDSA44 + ", "
											+ AlgorithmConstants.KEYALGORITHM_MLDSA65 + ", "
											+ AlgorithmConstants.KEYALGORITHM_MLDSA87 + ", "
											+ "]"));
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
						+ ecCurvesFormatted + ". Should be omitted for Ed25519 and Ed448, or ML_DSA44/65/87."));
	}

	private static final Logger log = Logger.getLogger(EnrollGenKeysCommand.class);

	@Override
	protected CommandResult execute(ParameterContainer parameters) {
		Security.addProvider(new BouncyCastleProvider());
		final String keySpec = parameters.get(KEYSPEC_ARG);
		String keyAlg = parameters.get(KEYALG_ARG);

		switch (keyAlg.toUpperCase()) {
		case "RSA":
			keyAlg = AlgorithmConstants.KEYALGORITHM_RSA;
			if (!RSA_KEY_SIZES.contains(keySpec)) {
				log.error("Key size " + keySpec + " is invalid for RSA Keys.");
				return CommandResult.CLI_FAILURE;
			}
			break;
		case "EC":
		case "ECDSA":
			keyAlg = AlgorithmConstants.KEYALGORITHM_EC;
			if (!EC_CURVES.contains(keySpec)) {
				log.error(keySpec + " is not a known EC curve.");
				return CommandResult.CLI_FAILURE;
			}
			break;
		case "ED25519":
			keyAlg = AlgorithmConstants.KEYALGORITHM_ED25519;
			break;
		case "ED448":
			keyAlg = AlgorithmConstants.KEYALGORITHM_ED448;
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
			KeyStore pkcs12 = createP12(getUsername(), this.privateKey, getCertificate(), getPassword());
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
			File p12File = new File(getDestination(), getUsername() + ".p12");
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

	private static KeyStore createP12(final String alias, final PrivateKey privateKey,
			final X509Certificate certificate, final String keystorePassword)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
		
		KeyStore store = KeyTools.createP12("Foo", privateKey, certificate, (X509Certificate) null, KeyStoreCipher.PKCS12_AES256_AES128);
		return store;
		
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
		return generateCertificateRequest(userdn, subjectAltName, publicKey, privateKey);
	}

}
