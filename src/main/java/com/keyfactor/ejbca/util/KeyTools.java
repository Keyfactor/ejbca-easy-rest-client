/*************************************************************************
 *                                                                       *
 *  Keyfactor Community                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.ejbca.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 */
public class KeyTools {

	public static final String KEYALGORITHM_RSA = "RSA";
	public static final String KEYALGORITHM_EC = "EC";
	public static final String KEYALGORITHM_ECDSA = "ECDSA"; // The same as "EC", just named differently sometimes. "EC"
																// and "ECDSA" should be handled in the same way
	public static final String KEYALGORITHM_ED25519 = "Ed25519";
	public static final String KEYALGORITHM_ED448 = "Ed448";

	private static final Logger log = LogManager.getLogger(KeyTools.class);

	private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";

	/**
	 * Get the ASN.1 encoded PublicKey as a Java PublicKey Object.
	 * 
	 * @param asn1EncodedPublicKey the ASN.1 encoded PublicKey
	 * @return the ASN.1 encoded PublicKey as a Java Object
	 */
	public static PublicKey getPublicKeyFromBytes(byte[] asn1EncodedPublicKey) {
		try {
			final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(asn1EncodedPublicKey);
			final AlgorithmIdentifier keyAlg = keyInfo.getAlgorithm();
			final X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString(keyInfo).getBytes());
			final KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(),
					BouncyCastleProvider.PROVIDER_NAME);
			return keyFact.generatePublic(xKeySpec);
		} catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException
				| IllegalArgumentException e) {
			log.error("Unable to decode PublicKey.", e);
		}
		return null;
	}

	/**
	 * Get the ASN.1 encoded PublicKey as a Java PublicKey Object.
	 * 
	 * @param asn1EncodedPublicKey the ASN.1 encoded PublicKey
	 * @return the ASN.1 encoded PublicKey as a Java Object
	 */
	public static PrivateKey getPrivateKeyFromBytes(byte[] asn1EncodedPrivateKey) {
		try {
			final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(asn1EncodedPrivateKey);
			final AlgorithmIdentifier keyAlg = privateKeyInfo.getPrivateKeyAlgorithm();
			final X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString(privateKeyInfo).getBytes());
			final KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(),
					BouncyCastleProvider.PROVIDER_NAME);
			return keyFact.generatePrivate(xKeySpec);
		} catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException
				| IllegalArgumentException e) {
			log.error("Unable to decode PublicKey.", e);
		}
		return null;
	}

	/**
	 * Extracts the binary DER data from a public key file. The file may be either
	 * in PEM format or in DER format. In the latter case, the file contents is
	 * returned as-is.
	 * 
	 * @param file Data of a PEM or DER file.
	 * @return DER encoded public key.
	 * @throws CertificateParsingException If the data isn't a public key in either
	 *                                     PEM or DER format.
	 */
	public static byte[] getBytesFromPublicKeyFile(final byte[] file) throws CertificateParsingException {
		if (file.length == 0) {
			throw new CertificateParsingException("Public key file is empty");
		}
		final String fileText = StandardCharsets.US_ASCII.decode(java.nio.ByteBuffer.wrap(file)).toString();
		final byte[] asn1bytes;
		{
			final byte[] tmpBytes = getBytesFromPEM(fileText, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
			asn1bytes = tmpBytes != null ? tmpBytes : file; // Assume it's in ASN1 format already if null
		}
		try {
			PublicKeyFactory.createKey(asn1bytes); // Check that it's a valid public key
			return asn1bytes;
		} catch (IOException | IllegalArgumentException e) {
			throw new CertificateParsingException("File is neither a valid PEM nor DER file.", e);
		}
	}

	/**
	 * Extracts the binary data from a PEM of a specified kind, e.g. public key.
	 * 
	 * @param pem         PEM data to extract from. May contain other types of data
	 *                    as well.
	 * @param beginMarker E.g. CertTools.BEGIN_PUBLIC_KEY
	 * @param endMarker   E.g. CertTools.END_PUBLIC_KEY
	 * @return The first entry of the matching type, or null if it couldn't be
	 *         parsed.
	 */
	public static byte[] getBytesFromPEM(String pem, String beginMarker, String endMarker) {
		final int start = pem.indexOf(beginMarker);
		final int end = pem.indexOf(endMarker, start);
		if (start == -1 || end == -1) {
			log.debug("Could not find " + beginMarker + " and " + endMarker + " lines in PEM");
			return null;
		}

		final String base64 = pem.substring(start + beginMarker.length(), end);
		return Base64.decode(base64.getBytes(StandardCharsets.US_ASCII));
	}

	/**
	 * Generates a keypair
	 * 
	 * @param keySpec string specification of keys to generate, typical value is
	 *                2048 for RSA keys, 1024 for DSA keys, secp256r1 for ECDSA
	 *                keys, Ed25519 or Ed448 for EdDSA or null if algspec is to be
	 *                used.
	 * @param keyAlg  algorithm of keys to generate, typical value is RSA, DSA or
	 *                ECDSA, see AlgorithmConstants.KEYALGORITHM_XX, if value is
	 *                Ed25519 or Ed448, not keySpec or algSpec is needed
	 * 
	 * @see org.cesecore.certificates.util.AlgorithmConstants
	 * @see org.bouncycastle.asn1.x9.X962NamedCurves
	 * @see org.bouncycastle.asn1.nist.NISTNamedCurves
	 * @see org.bouncycastle.asn1.sec.SECNamedCurves
	 * @see KeyTools#getKeyGenSpec(PublicKey)
	 * 
	 * @return KeyPair the generated keypair
	 * @throws InvalidAlgorithmParameterException if the given parameters are
	 *                                            inappropriate for this key pair
	 *                                            generator.
	 * @see org.cesecore.certificates.util.AlgorithmConstants#KEYALGORITHM_RSA
	 */
	public static KeyPair genKeys(final String keySpec, final String keyAlg) throws InvalidAlgorithmParameterException {
		final KeyPairGenerator keygen;
		try {
			// A small note on RSA keys.
			// RSA keys are encoded as a SubjectPublicKeyInfo in X.509 certificates (public
			// key) and PKCS#8 private key blobs (private key)
			// In a SubjectPublicKeyInfo encoded is as an AlgorithmIdentifier, which has an
			// OID and parameters.
			// See section 1.2 in https://tools.ietf.org/html/rfc4055
			// and section 2.1 in https://tools.ietf.org/html/rfc4056
			// The "normal" OID used is rsaEncryption, but it can also be id-RSASSA-PSS
			// "When the RSA private key owner wishes to limit the use of the public
			// key exclusively to RSASSA-PSS" (quote from RFC4055). How it's encoded can be
			// controlled during key generation. We use "RSA" for
			// RSA keys, which means rsaEncryption. Albeit we don't see any need right now
			// (May 2020), it is possible to use id-RSASSA-PSS if
			// on uses RSASSA-PSS instead of RSA when creating the KeyPairGeneratos, i.e.
			// KeyPairGenerator.getInstance("RSASSA-PSS",
			// BouncyCastleProvider.PROVIDER_NAME)
			keygen = KeyPairGenerator.getInstance(keyAlg, BouncyCastleProvider.PROVIDER_NAME);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Algorithm " + keyAlg + " was not recognized.", e);
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
		}
		if (StringUtils.equals(keyAlg, KEYALGORITHM_ECDSA) || StringUtils.equals(keyAlg, KEYALGORITHM_EC)) {
			if ((keySpec != null) && !StringUtils.equals(keySpec, "implicitlyCA")) {
				log.debug("Generating named curve ECDSA key pair: " + keySpec);
				// Check if we have an OID for this named curve
				if (ECUtil.getNamedCurveOid(keySpec) != null) {
					ECGenParameterSpec bcSpec = new ECGenParameterSpec(keySpec);
					keygen.initialize(bcSpec, new SecureRandom());
				} else {
					if (log.isDebugEnabled()) {
						log.debug("Curve did not have an OID in BC, trying to pick up Parameter spec: " + keySpec);
					}
					// This may be a new curve without OID, like curve25519 and we have to do
					// something a bit different
					X9ECParameters ecP = CustomNamedCurves.getByName(keySpec);
					if (ecP == null) {
						throw new InvalidAlgorithmParameterException(
								"Can not generate EC curve, no OID and no ECParameters found: " + keySpec);
					}
					org.bouncycastle.jce.spec.ECParameterSpec ecSpec = new org.bouncycastle.jce.spec.ECParameterSpec(
							ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
					keygen.initialize(ecSpec, new SecureRandom());
				}
			} else if (StringUtils.equals(keySpec, "implicitlyCA")) {
				log.debug("Generating implicitlyCA encoded ECDSA key pair");
				// If the keySpec is null, we have "implicitlyCA" defined EC parameters. The
				// parameters were already installed when we installed the provider
				// We just make sure that ecSpec == null here
				keygen.initialize(null, new SecureRandom());
			} else {
				throw new InvalidAlgorithmParameterException("No keySpec no algSpec and no implicitlyCA specified");
			}
		} else if (StringUtils.isNumeric(keySpec) && !StringUtils.startsWith(keyAlg, "Ed")) {
			// RSA or DSA key where keyspec is simply the key length
			// If it is Ed, be nice and ignore the keysize
			final int keysize = Integer.parseInt(keySpec);
			keygen.initialize(keysize);
		}
		// If KeyAlg is Ed448 or Ed25519, we don't even need a keySpec
		return keygen.generateKeyPair();

	}

	public static KeyStore createP12(final String alias, final PrivateKey privateKey, final X509Certificate certificate, final String keystorePassword)
			throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyStore store;
		try {
			store = KeyStore.getInstance("PKCS12-3DES-3DES", BouncyCastleProvider.PROVIDER_NAME);
			store.load(null, keystorePassword.toCharArray());
		} catch (KeyStoreException | NoSuchProviderException | IOException e) {
			throw new IllegalStateException("Could not create keystore.", e);
		}
		

		// Certificate chain
		if (certificate == null) {
			throw new IllegalArgumentException("Parameter certificate cannot be null.");
		}
		final Certificate[] chain = new Certificate[1];

		CertificateFactory certificateFactory;
		try {
			certificateFactory = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
		} catch (CertificateException | NoSuchProviderException e) {
			throw new CertificateParsingException("Could not create certificate factory", e);
		}
		chain[0] = certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
		// Set attributes on user-certificate
		try {
			final PKCS12BagAttributeCarrier certBagAttr = (PKCS12BagAttributeCarrier) chain[0];
			certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
			// in this case we just set the local key id to that of the public key
			certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId,
					createSubjectKeyId(chain[0].getPublicKey()));
		} catch (ClassCastException e) {
			log.error("ClassCastException setting BagAttributes, can not set friendly name: ", e);
		}
		try {
			// "Clean" private key, i.e. remove any old attributes,
			// As well as convert any EdDSA key to v1 format that is understood by openssl
			// v1.1.1 and earlier
			// EdDSA (Ed25519 or Ed448) keys have a v1 format, with only the private key,
			// and a v2 format that includes both the private and public
			final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			final PrivateKeyInfo v1PkInfo = new PrivateKeyInfo(pkInfo.getPrivateKeyAlgorithm(),
					pkInfo.parsePrivateKey());
			final KeyFactory keyfact = KeyFactory.getInstance(privateKey.getAlgorithm(),
					BouncyCastleProvider.PROVIDER_NAME);
			final PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(v1PkInfo.getEncoded()));
			// The PKCS#12 bag attributes PKCSObjectIdentifiers.pkcs_9_at_friendlyName and
			// PKCSObjectIdentifiers.pkcs_9_at_localKeyId
			// are set automatically by BC when setting the key entry
			store.setKeyEntry(alias, pk, null, chain);

			return store;
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException("BouncyCastle provider was not found.", e);
		} catch (KeyStoreException e) {
			throw new IllegalStateException("PKCS12 keystore type could not be instanced.", e);
		} catch (IOException e) {
			throw new IllegalStateException("IOException should not be thrown when instancing an empty keystore.", e);
		}
	}
	
    /**
     * create the subject key identifier.
     * 
     * @param pubKey
     *            the public key
     * 
     * @return SubjectKeyIdentifer asn.1 structure
     */
    private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey pubKey) {
        try {
            final ASN1Sequence keyASN1Sequence;
            try( final ASN1InputStream pubKeyAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(pubKey.getEncoded())); ) {
                final Object keyObject = pubKeyAsn1InputStream.readObject();
                if (keyObject instanceof ASN1Sequence) {
                    keyASN1Sequence = (ASN1Sequence) keyObject;
                } else {
                    // PublicKey key that doesn't encode to a ASN1Sequence. Fix this by creating a BC object instead.
                    final PublicKey altKey = (PublicKey) KeyFactory.getInstance(pubKey.getAlgorithm(), BouncyCastleProvider.PROVIDER_NAME).translateKey(pubKey);
                    try ( final ASN1InputStream altKeyAsn1InputStream = new ASN1InputStream(new ByteArrayInputStream(altKey.getEncoded())) ) {
                        keyASN1Sequence = (ASN1Sequence) altKeyAsn1InputStream.readObject();
                    }
                }
                X509ExtensionUtils x509ExtensionUtils = new BcX509ExtensionUtils();
                return x509ExtensionUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(keyASN1Sequence));
            }
        } catch (Exception e) {
            final RuntimeException e2 = new RuntimeException("error creating key"); // NOPMD
            e2.initCause(e);
            throw e2;
        }
    } 
}
