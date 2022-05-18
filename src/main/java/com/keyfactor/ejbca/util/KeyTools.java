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
package com.keyfactor.ejbca.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 */
public class KeyTools {

	private static final Logger log = LogManager.getLogger(KeyTools.class);
	
	private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
	
    /** 
     * Get the ASN.1 encoded PublicKey as a Java PublicKey Object.
     * @param asn1EncodedPublicKey the ASN.1 encoded PublicKey
     * @return the ASN.1 encoded PublicKey as a Java Object
     */
    public static PublicKey getPublicKeyFromBytes(byte[] asn1EncodedPublicKey) {
        try {
            final SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(asn1EncodedPublicKey);
            final AlgorithmIdentifier keyAlg = keyInfo.getAlgorithm();
            final X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString(keyInfo).getBytes());
            final KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            return keyFact.generatePublic(xKeySpec);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | IllegalArgumentException e) {
            log.error("Unable to decode PublicKey.", e);
        }
        return null;
    }
    
    /** 
     * Get the ASN.1 encoded PublicKey as a Java PublicKey Object.
     * @param asn1EncodedPublicKey the ASN.1 encoded PublicKey
     * @return the ASN.1 encoded PublicKey as a Java Object
     */
    public static PrivateKey getPrivateKeyFromBytes(byte[] asn1EncodedPrivateKey) {
        try {
        	final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(asn1EncodedPrivateKey);
            final AlgorithmIdentifier keyAlg = privateKeyInfo.getPrivateKeyAlgorithm();
            final X509EncodedKeySpec xKeySpec = new X509EncodedKeySpec(new DERBitString(privateKeyInfo).getBytes());
            final KeyFactory keyFact = KeyFactory.getInstance(keyAlg.getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            return keyFact.generatePrivate(xKeySpec);
        } catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | IllegalArgumentException e) {
            log.error("Unable to decode PublicKey.", e);
        }
        return null;
    }
    
    /**
     * Extracts the binary DER data from a public key file. The file may be either in PEM format
     * or in DER format. In the latter case, the file contents is returned as-is.
     *  
     * @param file Data of a PEM or DER file.
     * @return DER encoded public key.
     * @throws CertificateParsingException If the data isn't a public key in either PEM or DER format.
     */
    public static byte[] getBytesFromPublicKeyFile(final byte[] file) throws CertificateParsingException {
        if (file.length == 0) {
            throw new CertificateParsingException("Public key file is empty");
        }
        final String fileText = StandardCharsets.US_ASCII.decode(java.nio.ByteBuffer.wrap(file)).toString();
        final byte[] asn1bytes;
        {
            final byte[] tmpBytes = getBytesFromPEM(fileText, BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
            asn1bytes = tmpBytes!=null ? tmpBytes : file; // Assume it's in ASN1 format already if null
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
     * @param pem PEM data to extract from. May contain other types of data as well.
     * @param beginMarker E.g. CertTools.BEGIN_PUBLIC_KEY
     * @param endMarker E.g. CertTools.END_PUBLIC_KEY
     * @return The first entry of the matching type, or null if it couldn't be parsed.
     */
    public static byte[] getBytesFromPEM(String pem, String beginMarker, String endMarker) {
        final int start = pem.indexOf(beginMarker);
        final int end = pem.indexOf(endMarker, start);
        if (start == -1 || end == -1) {
            log.debug("Could not find "+beginMarker+" and "+endMarker+" lines in PEM");
            return null;
        }
        
        final String base64 = pem.substring(start + beginMarker.length(), end);
        return Base64.decode(base64.getBytes(StandardCharsets.US_ASCII));
    }
}
