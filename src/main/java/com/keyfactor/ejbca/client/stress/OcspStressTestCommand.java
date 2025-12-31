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
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.io.IOUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.ejbca.client.ErceCommandBase;
import com.keyfactor.util.CertTools;

import org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler;

/**
 * A CLI command for performing OCSP stress testing.
 * Sends multi-threaded OCSP requests to test OCSP responder performance.
 *
 * NOTE: This command overrides the base class to make --authkeystore and --hostname optional
 * since OCSP stress testing can work against HTTP endpoints without authentication.
 */
public class OcspStressTestCommand extends ErceCommandBase {

    private static final Logger log = Logger.getLogger(OcspStressTestCommand.class);

    private static final String OCSP_URL_ARG = "--ocspurl";
    private static final String OCSP_SN_FILE_ARG = "--ocspsnfile";
    private static final String CA_CERT_FILE_ARG = "--cacertfile";
    private static final String THREADS_ARG = "--threads";
    private static final String WAIT_TIME_ARG = "--waittime";
    private static final String REQ_TYPE_ARG = "--reqtype";
    private static final String NONCE_LEN_ARG = "--ocspnoncelen";
    private static final String DURATION_ARG = "--duration";
    private static final String RANDOM_WAIT_ARG = "--randomwait";
    private static final String VERIFY_NONCE_ARG = "--verifynonce";
    private static final String OCSP_AUTH_STORE_ARG = "--ocspauthstore";
    private static final String OCSP_AUTH_PASSWD_ARG = "--ocspauthpasswd";
    private static final String SAVE_OCSP_ARG = "--saveocsp";
    private static final String OUTPUT_FORMAT_ARG = "--outputformat";
    private static final String OUTPUT_FILE_ARG = "--outputfile";
    private static final String PROGRESS_INTERVAL_ARG = "--progressinterval";

    // Base class parameter names (to override them as optional)
    private static final String AUTH_KEYSTORE_ARG = "--authkeystore";
    private static final String HOSTNAME_ARG = "--hostname";

    // Volatile flag to signal threads to stop
    private volatile boolean stopRequested = false;

    // Volatile counters for real-time progress tracking
    private volatile long totalRequestsCompleted = 0;
    private volatile long totalSuccessfulRequests = 0;
    private volatile long totalFailedRequests = 0;

    {
        // Register OCSP-specific parameters
        // Note: --authkeystore and --hostname are inherited from base class but automatically injected
        registerParameter(new Parameter(OCSP_URL_ARG, "OCSP URL", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "OCSP responder URL, e.g. http://myhost:8080/ejbca/publicweb/status/ocsp"));
        registerParameter(new Parameter(OCSP_SN_FILE_ARG, "Serial number file", MandatoryMode.MANDATORY,
                StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Certificate serial number file. Either simple list (one per line) or pipe-delimited format from --savecerts"));
        registerParameter(new Parameter(CA_CERT_FILE_ARG, "CA certificate file", MandatoryMode.MANDATORY,
                StandaloneMode.FORBID, ParameterMode.ARGUMENT, "PEM-encoded CA certificate file"));
        registerParameter(new Parameter(THREADS_ARG, "Number of threads", MandatoryMode.MANDATORY,
                StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Number of concurrent threads"));
        registerParameter(new Parameter(WAIT_TIME_ARG, "Wait time (ms)", MandatoryMode.MANDATORY,
                StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Milliseconds to wait between requests per thread"));
        registerParameter(new Parameter(REQ_TYPE_ARG, "Request type", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "OCSP request method. Options:\n" +
                "  POST (default) - Standard OCSP POST request with Content-Type: application/ocsp-request\n" +
                "  GET - OCSP GET request with Base64-encoded request in URL path\n" +
                "Default: POST\n" +
                "Note: RFC 6960 Section A.1 recommends that GET requests longer than 255 bytes\n" +
                "after encoding SHOULD use POST instead. Signed OCSP requests are typically much\n" +
                "larger than unsigned requests and may exceed this limit."));
        registerParameter(new Parameter(NONCE_LEN_ARG, "Nonce length", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Nonce length in bytes. Default: 32. Set to 0 to disable nonce"));
        registerParameter(new Parameter(DURATION_ARG, "Duration (seconds)", MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Test duration in seconds. Default: run indefinitely until interrupted"));
        registerParameter(new Parameter(RANDOM_WAIT_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG, "Use random wait time between 0 and --waittime ms"));
        registerParameter(new Parameter(VERIFY_NONCE_ARG, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.FLAG, "Verify that OCSP response nonce matches request nonce. Only applicable when nonce is enabled"));
        registerParameter(new Parameter(OCSP_AUTH_STORE_ARG, "Keystore file", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Keystore file (P12/JKS) containing private key and certificate for signing OCSP requests"));
        registerParameter(new Parameter(OCSP_AUTH_PASSWD_ARG, "Keystore password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Password for the OCSP request signing keystore"));
        registerParameter(new Parameter(SAVE_OCSP_ARG, "Directory path", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Directory path to save OCSP requests and responses for debugging (e.g., ./ocsp-debug)"));
        registerParameter(new Parameter(OUTPUT_FORMAT_ARG, "Output format", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Output format for test results. Options: 'console' (default), 'csv', 'markdown'. When csv or markdown is specified, --outputfile is required."));
        registerParameter(new Parameter(OUTPUT_FILE_ARG, "Output file", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "File path to save test results in CSV or Markdown format. Required when --outputformat is csv or markdown."));
        registerParameter(new Parameter(PROGRESS_INTERVAL_ARG, "Progress interval (seconds)", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Interval in seconds for displaying real-time progress updates. Default: 5 seconds. Set to 0 to disable progress updates."));
    }

    /**
     * Inner class to hold certificate information
     */
    private static class CertificateInfo {
        String serialNumber;
        String issuerDn;

        CertificateInfo(String serialNumber, String issuerDn) {
            this.serialNumber = serialNumber;
            this.issuerDn = issuerDn;
        }
    }

    /**
     * Inner class to hold OCSP request with nonce
     */
    private static class OcspRequestWithNonce {
        OCSPReq request;
        byte[] nonce;

        OcspRequestWithNonce(OCSPReq request, byte[] nonce) {
            this.request = request;
            this.nonce = nonce;
        }
    }

    /**
     * Inner class to hold test results from each thread
     */
    private static class OcspTestResult {
        List<String> failures;
        Map<String, Integer> statusCounts;
        List<Long> responseTimes;

        OcspTestResult() {
            this.failures = new ArrayList<>();
            this.statusCounts = new HashMap<>();
            this.responseTimes = new ArrayList<>();
        }
    }

    /**
     * Override base class execute to automatically inject dummy authentication parameters
     * since OCSP stress testing doesn't require keystore authentication
     */
    @Override
    public CommandResult execute(String... arguments) {
        // Inject dummy values for base class mandatory parameters if not provided
        List<String> modifiedArgs = new ArrayList<>();
        boolean hasAuthKeystore = false;
        boolean hasHostname = false;

        for (String arg : arguments) {
            modifiedArgs.add(arg);
            if (arg.equals(AUTH_KEYSTORE_ARG)) {
                hasAuthKeystore = true;
            } else if (arg.equals(HOSTNAME_ARG)) {
                hasHostname = true;
            }
        }

        // Add dummy values if not provided by user
        if (!hasAuthKeystore) {
            modifiedArgs.add(AUTH_KEYSTORE_ARG);
            modifiedArgs.add("/dev/null");
        }
        if (!hasHostname) {
            modifiedArgs.add(HOSTNAME_ARG);
            modifiedArgs.add("localhost:8080");
        }

        ParameterContainer parameters = parameterHandler.parseParameters(
            modifiedArgs.toArray(new String[0])
        );
        if (parameters == null) {
            return CommandResult.CLI_FAILURE;
        }
        if (parameters.containsKey(ParameterHandler.HELP_KEY)) {
            printManPage();
            return CommandResult.SUCCESS;
        }
        // Skip the base class's keystore password validation - not needed for OCSP
        return execute(parameters);
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final String ocspUrl = parameters.get(OCSP_URL_ARG);
        final String serialNumberFile = parameters.get(OCSP_SN_FILE_ARG);
        final String caCertFile = parameters.get(CA_CERT_FILE_ARG);
        final String reqType = parameters.get(REQ_TYPE_ARG) != null ? parameters.get(REQ_TYPE_ARG) : "POST";

        final int numberOfThreads;
        try {
            numberOfThreads = Integer.parseInt(parameters.get(THREADS_ARG));
        } catch (NumberFormatException e) {
            log.error(THREADS_ARG + " was not a numeric value");
            return CommandResult.CLI_FAILURE;
        }
        if (numberOfThreads < 1) {
            log.error(THREADS_ARG + " must be a positive value");
            return CommandResult.CLI_FAILURE;
        }

        final int waitTime;
        try {
            waitTime = Integer.parseInt(parameters.get(WAIT_TIME_ARG));
        } catch (NumberFormatException e) {
            log.error(WAIT_TIME_ARG + " was not a numeric value");
            return CommandResult.CLI_FAILURE;
        }
        if (waitTime < 0) {
            log.error(WAIT_TIME_ARG + " must be non-negative");
            return CommandResult.CLI_FAILURE;
        }

        final int nonceLength;
        if (parameters.get(NONCE_LEN_ARG) != null) {
            try {
                nonceLength = Integer.parseInt(parameters.get(NONCE_LEN_ARG));
            } catch (NumberFormatException e) {
                log.error(NONCE_LEN_ARG + " was not a numeric value");
                return CommandResult.CLI_FAILURE;
            }
        } else {
            nonceLength = 32;
        }

        final boolean verifyNonce = parameters.containsKey(VERIFY_NONCE_ARG);

        final long duration;
        if (parameters.get(DURATION_ARG) != null) {
            try {
                duration = Long.parseLong(parameters.get(DURATION_ARG)) * 1000L; // Convert to ms
            } catch (NumberFormatException e) {
                log.error(DURATION_ARG + " was not a numeric value");
                return CommandResult.CLI_FAILURE;
            }
        } else {
            duration = Long.MAX_VALUE; // Run indefinitely
        }

        final boolean randomWait = parameters.containsKey(RANDOM_WAIT_ARG);

        // Parse OCSP request signing parameters
        final String ocspAuthStore = parameters.get(OCSP_AUTH_STORE_ARG);
        final String ocspAuthPasswd = parameters.get(OCSP_AUTH_PASSWD_ARG);

        // Validate: if one is provided, both must be provided
        if ((ocspAuthStore != null && ocspAuthPasswd == null) || (ocspAuthStore == null && ocspAuthPasswd != null)) {
            log.error("Both " + OCSP_AUTH_STORE_ARG + " and " + OCSP_AUTH_PASSWD_ARG + " must be specified together for request signing");
            return CommandResult.CLI_FAILURE;
        }

        // Parse save OCSP debug files parameter
        final String saveOcspDir = parameters.get(SAVE_OCSP_ARG);
        if (saveOcspDir != null) {
            File dir = new File(saveOcspDir);
            if (!dir.exists()) {
                if (!dir.mkdirs()) {
                    log.error("Failed to create directory: " + saveOcspDir);
                    return CommandResult.CLI_FAILURE;
                }
                log.info("Created directory for OCSP debug files: " + saveOcspDir);
            } else if (!dir.isDirectory()) {
                log.error("Path exists but is not a directory: " + saveOcspDir);
                return CommandResult.CLI_FAILURE;
            }
        }

        // Parse output format parameters
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
                progressInterval = Integer.parseInt(parameters.get(PROGRESS_INTERVAL_ARG));
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

        // Load certificate serial numbers
        List<CertificateInfo> certList = loadCertificateInfo(serialNumberFile);
        if (certList == null || certList.isEmpty()) {
            log.error("No certificate serial numbers loaded from file: " + serialNumberFile);
            return CommandResult.CLI_FAILURE;
        }
        log.info("Loaded " + certList.size() + " certificate serial numbers");

        // Load CA certificate
        X509Certificate caCert = loadCaCertificate(caCertFile);
        if (caCert == null) {
            log.error("Failed to load CA certificate from file: " + caCertFile);
            return CommandResult.CLI_FAILURE;
        }
        log.info("Loaded CA certificate: " + caCert.getSubjectDN().toString());

        // Load signing credentials if provided
        final java.security.PrivateKey signingKey;
        final X509Certificate[] signingCertChain;
        if (ocspAuthStore != null && ocspAuthPasswd != null) {
            try {
                Object[] credentials = loadSigningCredentials(ocspAuthStore, ocspAuthPasswd);
                signingKey = (java.security.PrivateKey) credentials[0];
                signingCertChain = (X509Certificate[]) credentials[1];
                log.info("Loaded OCSP request signing credentials from: " + ocspAuthStore);
                log.info("Signing certificate: " + signingCertChain[0].getSubjectDN().toString());
            } catch (Exception e) {
                log.error("Failed to load signing credentials: " + e.getMessage());
                return CommandResult.CLI_FAILURE;
            }
        } else {
            signingKey = null;
            signingCertChain = null;
        }

        // Start the stress test
        log.info("Starting OCSP stress test with " + numberOfThreads + " threads");
        log.info("OCSP URL: " + ocspUrl);
        log.info("Request type: " + reqType);
        log.info("Wait time: " + waitTime + " ms" + (randomWait ? " (random)" : ""));
        log.info("Duration: " + (duration == Long.MAX_VALUE ? "unlimited" : (duration / 1000) + " seconds"));

        long startTime = System.currentTimeMillis();
        final List<CompletableFuture<OcspTestResult>> futures = new ArrayList<>();
        Random random = new Random();

        // Reset counters
        totalRequestsCompleted = 0;
        totalSuccessfulRequests = 0;
        totalFailedRequests = 0;

        // Start progress tracking thread if enabled
        Thread progressThread = null;
        if (progressInterval > 0) {
            progressThread = new Thread(() -> {
                long lastCompleted = 0;
                long lastTime = System.currentTimeMillis();

                while (!stopRequested) {
                    try {
                        Thread.sleep(progressInterval * 1000L);

                        if (stopRequested) {
                            break;
                        }

                        long currentTime = System.currentTimeMillis();
                        long currentCompleted = totalRequestsCompleted;
                        long intervalRequests = currentCompleted - lastCompleted;
                        double intervalSeconds = (currentTime - lastTime) / 1000.0;
                        double requestsPerSec = intervalSeconds > 0 ? intervalRequests / intervalSeconds : 0;

                        System.out.println(String.format("Progress: %d requests (%d successful, %d failed) - %.2f req/s",
                                currentCompleted, totalSuccessfulRequests, totalFailedRequests, requestsPerSec));

                        lastCompleted = currentCompleted;
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

        // Add shutdown hook to gracefully handle Ctrl+C
        Thread shutdownHook = new Thread(() -> {
            System.out.println("\nShutdown signal received, stopping test and calculating statistics...");
            stopRequested = true;

            // Give threads a moment to finish current requests
            try {
                Thread.sleep(500);
            } catch (InterruptedException ignored) {
            }

            // Collect and report statistics
            long endTime = System.currentTimeMillis();
            long actualDuration = endTime - startTime;

            List<OcspTestResult> results = new ArrayList<>();
            for (CompletableFuture<OcspTestResult> future : futures) {
                try {
                    results.add(future.getNow(new OcspTestResult()));
                } catch (Exception e) {
                    // Ignore
                }
            }

            reportStatisticsToConsole(results, actualDuration);
        });
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        // Launch threads
        for (int threadNumber = 0; threadNumber < numberOfThreads; threadNumber++) {
            final int threadId = threadNumber;

            futures.add(CompletableFuture.supplyAsync(() -> {
                OcspTestResult result = new OcspTestResult();
                int requestCount = 0;

                while (shouldContinue(startTime, duration)) {
                    // Randomly select a certificate
                    CertificateInfo cert = certList.get(random.nextInt(certList.size()));

                    long requestStart = System.currentTimeMillis();
                    try {
                        // Build OCSP request
                        OcspRequestWithNonce requestWithNonce = buildOcspRequest(new BigInteger(cert.serialNumber, 16), caCert,
                                nonceLength, signingKey, signingCertChain);

                        // Save debug request if enabled
                        saveDebugRequest(requestWithNonce.request, saveOcspDir, threadId, requestCount);

                        // Send request
                        String status = sendOcspRequest(requestWithNonce.request, ocspUrl, reqType, caCert, requestWithNonce.nonce, verifyNonce, saveOcspDir, threadId, requestCount);
                        result.statusCounts.merge(status, 1, Integer::sum);

                        long responseTime = System.currentTimeMillis() - requestStart;
                        result.responseTimes.add(responseTime);

                        // Increment success counter
                        synchronized (OcspStressTestCommand.this) {
                            totalSuccessfulRequests++;
                        }

                    } catch (Exception e) {
                        String errorMsg = "Thread " + threadId + " - OCSP request failed for SN "
                                + cert.serialNumber + ": " + e.getMessage();
                        result.failures.add(errorMsg);
                        log.error(errorMsg);

                        // Increment failure counter
                        synchronized (OcspStressTestCommand.this) {
                            totalFailedRequests++;
                        }
                    }

                    // Increment total completed counter
                    synchronized (OcspStressTestCommand.this) {
                        totalRequestsCompleted++;
                    }

                    requestCount++;

                    // Wait between requests
                    if (waitTime > 0) {
                        try {
                            int actualWait = randomWait ? random.nextInt(waitTime + 1) : waitTime;
                            Thread.sleep(actualWait);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }

                // Use System.out for thread completion to ensure visibility during shutdown
                String completionMsg = "Thread " + threadId + " completed " + requestCount + " requests";
                if (stopRequested) {
                    System.out.println(completionMsg);
                } else {
                    log.info(completionMsg);
                }
                return result;
            }));
        }

        // Wait for all threads to complete
        CompletableFuture<Void> allFutures = CompletableFuture
                .allOf(futures.toArray(new CompletableFuture<?>[0]));

        try {
            allFutures.get();
        } catch (InterruptedException e) {
            log.info("\nTest interrupted, waiting for threads to finish...");
            stopRequested = true;
            // Wait a bit for threads to notice the stop flag
            try {
                Thread.sleep(100);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }
        } catch (ExecutionException e) {
            log.error("Thread execution error: " + e.getMessage());
        }

        long endTime = System.currentTimeMillis();
        long actualDuration = endTime - startTime;

        // Remove shutdown hook since we completed normally
        try {
            Runtime.getRuntime().removeShutdownHook(shutdownHook);
        } catch (IllegalStateException e) {
            // Shutdown already in progress, hook will handle statistics
            return CommandResult.SUCCESS;
        }

        // Collect results from all threads (even if interrupted)
        List<OcspTestResult> results = new ArrayList<>();
        for (CompletableFuture<OcspTestResult> future : futures) {
            try {
                // Use a short timeout to get whatever results are available
                results.add(future.getNow(new OcspTestResult()));
            } catch (Exception e) {
                log.error("Failed to get thread result: " + e.getMessage());
            }
        }

        // Report statistics
        reportStatistics(results, actualDuration);

        // Write results to file if requested
        if (outputFormat.equals("csv")) {
            try {
                writeResultsToCsv(outputFile, results, actualDuration);
                log.info("Results saved to " + outputFile);
            } catch (IOException e) {
                log.error("Failed to write CSV results to file: " + e.getMessage());
                return CommandResult.CLI_FAILURE;
            }
        } else if (outputFormat.equals("markdown")) {
            try {
                writeResultsToMarkdown(outputFile, results, actualDuration);
                log.info("Results saved to " + outputFile);
            } catch (IOException e) {
                log.error("Failed to write Markdown results to file: " + e.getMessage());
                return CommandResult.CLI_FAILURE;
            }
        }

        return CommandResult.SUCCESS;
    }

    /**
     * Check if the test should continue based on duration
     */
    private boolean shouldContinue(long startTime, long duration) {
        return !stopRequested && (System.currentTimeMillis() - startTime) < duration;
    }

    /**
     * Load certificate serial numbers from file
     * Supports two formats:
     * 1. Simple list: one serial number per line (decimal or hex with 0x prefix)
     * 2. Pipe-delimited: serialNumber|issuerDn (from --savecerts)
     */
    private List<CertificateInfo> loadCertificateInfo(String filename) {
        List<CertificateInfo> certs = new ArrayList<>();
        int lineNumber = 0;
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                try {
                    // Try pipe-delimited format first
                    if (line.contains("|")) {
                        String[] parts = line.split("\\|", 2);
                        certs.add(new CertificateInfo(parts[0], parts[1]));
                    } else {
                        // Simple serial number format
                        BigInteger serialNumber;
                        if (line.startsWith("0x") || line.startsWith("0X")) {
                            serialNumber = new BigInteger(line.substring(2), 16);
                        } else {
                            try {
                                serialNumber = new BigInteger(line, 16);
                            } catch (NumberFormatException e) {
                                // Try decimal format
                                serialNumber = new BigInteger(line);
                            }
                        }
                        certs.add(new CertificateInfo(serialNumber.toString(16).toUpperCase(), null));
                    }
                } catch (NumberFormatException e) {
                    log.warn("Skipping invalid serial number at line " + lineNumber + ": " + line);
                    continue;
                }
            }
        } catch (IOException e) {
            log.error("Failed to load certificate info: " + e.getMessage());
            return null;
        }
        return certs;
    }

    /**
     * Load CA certificate from PEM file
     */
    private X509Certificate loadCaCertificate(String filename) {
        try {
            List<X509Certificate> certs = CertTools.getCertsFromPEM(filename, X509Certificate.class);
            if (certs.isEmpty()) {
                log.error("No certificates found in CA certificate file");
                return null;
            }
            return certs.get(0);
        } catch (CertificateParsingException e) {
            log.error("Failed to parse CA certificate: " + e.getMessage());
            return null;
        } catch (Exception e) {
            log.error("Failed to load CA certificate: " + e.getMessage());
            return null;
        }
    }

    /**
     * Load signing credentials from keystore (P12 or JKS)
     * Returns array: [0] = PrivateKey, [1] = X509Certificate[]
     */
    private Object[] loadSigningCredentials(String keystorePath, String password) throws Exception {
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(keystorePath);

            // Try PKCS12 first
            java.security.KeyStore keystore = null;
            try {
                keystore = java.security.KeyStore.getInstance("PKCS12");
                keystore.load(fis, password.toCharArray());
            } catch (Exception e) {
                // If PKCS12 fails, try JKS
                fis.close();
                fis = new java.io.FileInputStream(keystorePath);
                keystore = java.security.KeyStore.getInstance("JKS");
                keystore.load(fis, password.toCharArray());
            }

            // Find the first private key entry
            java.util.Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (keystore.isKeyEntry(alias)) {
                    java.security.PrivateKey privateKey = (java.security.PrivateKey) keystore.getKey(alias, password.toCharArray());
                    java.security.cert.Certificate[] certChain = keystore.getCertificateChain(alias);

                    if (privateKey != null && certChain != null && certChain.length > 0) {
                        // Convert to X509Certificate array
                        X509Certificate[] x509Chain = new X509Certificate[certChain.length];
                        for (int i = 0; i < certChain.length; i++) {
                            x509Chain[i] = (X509Certificate) certChain[i];
                        }
                        return new Object[] { privateKey, x509Chain };
                    }
                }
            }

            throw new Exception("No private key entry found in keystore");
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * Build OCSP request for a certificate serial number
     * Returns OcspRequestWithNonce containing both the request and the nonce (if used)
     * Optionally signs the request if signing credentials are provided
     */
    private OcspRequestWithNonce buildOcspRequest(BigInteger serialNumber, X509Certificate caCert, int nonceLength,
            java.security.PrivateKey signingKey, X509Certificate[] signingCertChain)
            throws Exception {
        // Create digest calculator
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

        // Create certificate ID
        CertificateID certId = new CertificateID(digCalcProv.get(CertificateID.HASH_SHA1),
                new X509CertificateHolder(caCert.getEncoded()), serialNumber);

        // Build request
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(certId);

        // Add nonce extension
        byte[] nonce = null;
        if (nonceLength > 0) {
            nonce = new byte[nonceLength];
            new SecureRandom().nextBytes(nonce);
            Extension ext = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
                    new DEROctetString(nonce).getEncoded());
            builder.setRequestExtensions(new Extensions(ext));
        }

        // Sign the request if signing credentials are provided
        OCSPReq ocspReq;
        if (signingKey != null && signingCertChain != null && signingCertChain.length > 0) {
            // Set requestor name from the signing certificate
            X509CertificateHolder signingCertHolder = new X509CertificateHolder(signingCertChain[0].getEncoded());
            builder.setRequestorName(signingCertHolder.getSubject());

            // Convert certificate chain to Bouncy Castle format
            X509CertificateHolder[] certChainHolders = new X509CertificateHolder[signingCertChain.length];
            for (int i = 0; i < signingCertChain.length; i++) {
                certChainHolders[i] = new X509CertificateHolder(signingCertChain[i].getEncoded());
            }

            // Create content signer
            org.bouncycastle.operator.ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signingKey);

            // Build signed request
            ocspReq = builder.build(signer, certChainHolders);
        } else {
            // Build unsigned request
            ocspReq = builder.build();
        }

        return new OcspRequestWithNonce(ocspReq, nonce);
    }

    /**
     * Send OCSP request and return certificate status
     */
    private String sendOcspRequest(OCSPReq ocspReq, String ocspUrl, String reqType, X509Certificate caCert, byte[] requestNonce, boolean verifyNonce, String saveOcspDir, int threadId, int requestNum) throws Exception {
        byte[] requestBytes = ocspReq.getEncoded();

        CloseableHttpResponse response;

        // Create a simple HTTP client (supports both HTTP and HTTPS)
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            switch (reqType.toUpperCase()) {
            case "POST":
                HttpPost postRequest = new HttpPost(ocspUrl);
                postRequest.setHeader("Content-Type", "application/ocsp-request");
                postRequest.setEntity(new ByteArrayEntity(requestBytes));
                response = httpClient.execute(postRequest);
                break;

            case "GET":
                // Encode OCSP request as Base64 per RFC 6960 Section A.1.1
                byte[] base64Bytes = org.bouncycastle.util.encoders.Base64.encode(requestBytes);
                String base64Req = new String(base64Bytes, java.nio.charset.StandardCharsets.US_ASCII);

                // EJBCA's OCSP servlet expects standard Base64 with URL encoding
                // It uses URLDecoder.decode() then replaces spaces with '+' before Base64 decoding
                // So we need to percent-encode the Base64 special characters
                String urlEncodedBase64 = base64Req
                    .replace("+", "%2B")  // Percent-encode plus signs
                    .replace("/", "%2F")  // Percent-encode slashes
                    .replace("=", "%3D"); // Percent-encode padding

                String getUrl = ocspUrl + "/" + urlEncodedBase64;
                HttpGet getRequest = new HttpGet(getUrl);
                response = httpClient.execute(getRequest);
                break;

            default:
                throw new IllegalArgumentException("Unknown request type: " + reqType);
            }

            try {
                return parseOcspResponse(response, caCert, requestNonce, verifyNonce, saveOcspDir, threadId, requestNum);
            } finally {
                response.close();
            }
        }
    }

    /**
     * Parse OCSP response, verify signature, and extract certificate status
     */
    private String parseOcspResponse(CloseableHttpResponse response, X509Certificate caCert, byte[] requestNonce, boolean verifyNonce, String saveOcspDir, int threadId, int requestNum) throws Exception {
        int statusCode = response.getStatusLine().getStatusCode();

        if (statusCode != 200) {
            throw new Exception("HTTP error: " + statusCode);
        }

        byte[] responseBytes = IOUtils.toByteArray(response.getEntity().getContent());

        // Save debug response if enabled
        saveDebugResponse(responseBytes, saveOcspDir, threadId, requestNum);

        OCSPResp ocspResp = new OCSPResp(responseBytes);

        if (ocspResp.getStatus() != OCSPResp.SUCCESSFUL) {
            throw new Exception("OCSP response status: " + ocspResp.getStatus());
        }

        BasicOCSPResp basicResp = (BasicOCSPResp) ocspResp.getResponseObject();

        // Verify OCSP response signature
        if (!verifyOcspResponseSignature(basicResp, caCert)) {
            throw new Exception("OCSP response signature verification failed");
        }

        // Verify nonce if requested
        if (verifyNonce && requestNonce != null) {
            if (!verifyResponseNonce(basicResp, requestNonce)) {
                throw new Exception("OCSP response nonce verification failed");
            }
        }

        SingleResp[] responses = basicResp.getResponses();

        if (responses.length == 0) {
            throw new Exception("No responses in OCSP reply");
        }

        Object certStatus = responses[0].getCertStatus();

        if (certStatus == null) {
            return "GOOD";
        } else if (certStatus instanceof RevokedStatus) {
            return "REVOKED";
        } else if (certStatus instanceof UnknownStatus) {
            return "UNKNOWN";
        }

        return "UNKNOWN";
    }

    /**
     * Verify OCSP response signature using CA certificate
     */
    private boolean verifyOcspResponseSignature(BasicOCSPResp basicResp, X509Certificate caCert) {
        try {
            // Get certificates from OCSP response (OCSP responder certificate)
            org.bouncycastle.cert.X509CertificateHolder[] certs = basicResp.getCerts();

            if (certs != null && certs.length > 0) {
                // OCSP response is signed by a delegated OCSP responder certificate
                // Verify using the first certificate in the response (OCSP responder cert)
                org.bouncycastle.cert.X509CertificateHolder responderCert = certs[0];

                // Build content verifier using the OCSP responder's public key
                org.bouncycastle.operator.ContentVerifierProvider verifierProvider =
                    new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(responderCert);

                // Verify the OCSP response signature
                boolean signatureValid = basicResp.isSignatureValid(verifierProvider);

                if (!signatureValid) {
                    return false;
                }

                // TODO: Optionally verify that the OCSP responder certificate is trusted
                // (issued by the CA certificate or explicitly trusted)
                // For stress testing purposes, we trust the responder cert if signature is valid

                return true;
            } else {
                // OCSP response is signed directly by the CA certificate
                org.bouncycastle.operator.ContentVerifierProvider verifierProvider =
                    new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(caCert.getPublicKey());

                return basicResp.isSignatureValid(verifierProvider);
            }
        } catch (Exception e) {
            log.error("OCSP signature verification error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Verify that OCSP response nonce matches the request nonce
     */
    private boolean verifyResponseNonce(BasicOCSPResp basicResp, byte[] requestNonce) {
        try {
            // Get the nonce extension from the response
            Extension nonceExt = basicResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

            if (nonceExt == null) {
                log.error("OCSP response does not contain a nonce extension");
                return false;
            }

            // Extract the nonce value from the extension
            // The extension value is already a DEROctetString, and getExtnValue() returns its content
            // which is another DER-encoded octet string containing the actual nonce
            byte[] extnValueBytes = nonceExt.getExtnValue().getOctets();

            // Parse the inner DEROctetString to get the actual nonce bytes
            DEROctetString derNonce = (DEROctetString) DEROctetString.fromByteArray(extnValueBytes);
            byte[] actualNonce = derNonce.getOctets();

            // Compare the nonces
            if (requestNonce.length != actualNonce.length) {
                log.error("OCSP nonce length mismatch: request=" + requestNonce.length + ", response=" + actualNonce.length);
                return false;
            }

            for (int i = 0; i < requestNonce.length; i++) {
                if (requestNonce[i] != actualNonce[i]) {
                    log.error("OCSP nonce mismatch at position " + i);
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            log.error("OCSP nonce verification error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Save OCSP request to file for debugging
     */
    private void saveDebugRequest(OCSPReq ocspReq, String saveDir, int threadId, int requestNum) {
        if (saveDir == null) {
            return;
        }

        try {
            String filename = String.format("ocsp-req-t%d-r%d.der", threadId, requestNum);
            File debugFile = new File(saveDir, filename);
            Files.write(debugFile.toPath(), ocspReq.getEncoded());
        } catch (Exception e) {
            // Silently ignore debug save failures
            log.debug("Failed to save OCSP request: " + e.getMessage());
        }
    }

    /**
     * Save OCSP response to file for debugging
     */
    private void saveDebugResponse(byte[] responseBytes, String saveDir, int threadId, int requestNum) {
        if (saveDir == null) {
            return;
        }

        try {
            String filename = String.format("ocsp-resp-t%d-r%d.der", threadId, requestNum);
            File debugFile = new File(saveDir, filename);
            Files.write(debugFile.toPath(), responseBytes);
        } catch (Exception e) {
            // Silently ignore debug save failures
            log.debug("Failed to save OCSP response: " + e.getMessage());
        }
    }

    /**
     * Report aggregated statistics from all threads
     */
    private void reportStatistics(List<OcspTestResult> results, long duration) {
        // Aggregate counts
        long totalRequests = 0;
        long totalFailures = 0;
        Map<String, Integer> totalStatusCounts = new HashMap<>();
        List<Long> allResponseTimes = new ArrayList<>();

        for (OcspTestResult result : results) {
            totalRequests += result.responseTimes.size() + result.failures.size();
            totalFailures += result.failures.size();

            for (Map.Entry<String, Integer> entry : result.statusCounts.entrySet()) {
                totalStatusCounts.merge(entry.getKey(), entry.getValue(), Integer::sum);
            }

            allResponseTimes.addAll(result.responseTimes);
        }

        long successfulRequests = totalRequests - totalFailures;
        double executionTime = duration / 1000.0;

        log.info("");
        log.info("===== OCSP Stress Test Results =====");
        log.info("Total execution time: " + String.format("%.2f", executionTime) + " seconds");
        log.info("Total requests: " + totalRequests);
        log.info("Successful requests: " + successfulRequests);
        log.info("Failed requests: " + totalFailures);
        if (executionTime > 0) {
            log.info("Throughput: " + String.format("%.2f", totalRequests / executionTime) + " requests/second");
        }

        // Response time statistics
        if (!allResponseTimes.isEmpty()) {
            Collections.sort(allResponseTimes);
            long minTime = allResponseTimes.get(0);
            long maxTime = allResponseTimes.get(allResponseTimes.size() - 1);
            long avgTime = allResponseTimes.stream().mapToLong(Long::longValue).sum() / allResponseTimes.size();
            long p50Time = allResponseTimes.get(allResponseTimes.size() / 2);
            long p95Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.95));
            long p99Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.99));

            log.info("");
            log.info("Response Times (ms):");
            log.info("  Min: " + minTime);
            log.info("  Max: " + maxTime);
            log.info("  Avg: " + avgTime);
            log.info("  P50: " + p50Time);
            log.info("  P95: " + p95Time);
            log.info("  P99: " + p99Time);
        }

        // Certificate status breakdown
        if (!totalStatusCounts.isEmpty()) {
            log.info("");
            log.info("Certificate Status Distribution:");
            for (Map.Entry<String, Integer> entry : totalStatusCounts.entrySet()) {
                log.info("  " + entry.getKey() + ": " + entry.getValue());
            }
        }
    }

    /**
     * Report aggregated statistics from all threads to console (for shutdown hook)
     * Uses System.out instead of logger to ensure output during JVM shutdown
     */
    private void reportStatisticsToConsole(List<OcspTestResult> results, long duration) {
        // Aggregate counts
        long totalRequests = 0;
        long totalFailures = 0;
        Map<String, Integer> totalStatusCounts = new HashMap<>();
        List<Long> allResponseTimes = new ArrayList<>();

        for (OcspTestResult result : results) {
            totalRequests += result.responseTimes.size() + result.failures.size();
            totalFailures += result.failures.size();

            for (Map.Entry<String, Integer> entry : result.statusCounts.entrySet()) {
                totalStatusCounts.merge(entry.getKey(), entry.getValue(), Integer::sum);
            }

            allResponseTimes.addAll(result.responseTimes);
        }

        long successfulRequests = totalRequests - totalFailures;
        double executionTime = duration / 1000.0;

        System.out.println();
        System.out.println("===== OCSP Stress Test Results =====");
        System.out.println("Total execution time: " + String.format("%.2f", executionTime) + " seconds");
        System.out.println("Total requests: " + totalRequests);
        System.out.println("Successful requests: " + successfulRequests);
        System.out.println("Failed requests: " + totalFailures);
        if (executionTime > 0) {
            System.out.println("Throughput: " + String.format("%.2f", totalRequests / executionTime) + " requests/second");
        }

        // Response time statistics
        if (!allResponseTimes.isEmpty()) {
            Collections.sort(allResponseTimes);
            long minTime = allResponseTimes.get(0);
            long maxTime = allResponseTimes.get(allResponseTimes.size() - 1);
            long avgTime = allResponseTimes.stream().mapToLong(Long::longValue).sum() / allResponseTimes.size();
            long p50Time = allResponseTimes.get(allResponseTimes.size() / 2);
            long p95Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.95));
            long p99Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.99));

            System.out.println();
            System.out.println("Response Times (ms):");
            System.out.println("  Min: " + minTime);
            System.out.println("  Max: " + maxTime);
            System.out.println("  Avg: " + avgTime);
            System.out.println("  P50: " + p50Time);
            System.out.println("  P95: " + p95Time);
            System.out.println("  P99: " + p99Time);
        }

        // Certificate status breakdown
        if (!totalStatusCounts.isEmpty()) {
            System.out.println();
            System.out.println("Certificate Status Distribution:");
            for (Map.Entry<String, Integer> entry : totalStatusCounts.entrySet()) {
                System.out.println("  " + entry.getKey() + ": " + entry.getValue());
            }
        }
        System.out.println();
    }

    /**
     * Write test results to CSV file
     */
    private void writeResultsToCsv(String filename, List<OcspTestResult> results, long duration) throws IOException {
        // Aggregate counts
        long totalRequests = 0;
        long totalFailures = 0;
        Map<String, Integer> totalStatusCounts = new HashMap<>();
        List<Long> allResponseTimes = new ArrayList<>();

        for (OcspTestResult result : results) {
            totalRequests += result.responseTimes.size() + result.failures.size();
            totalFailures += result.failures.size();

            for (Map.Entry<String, Integer> entry : result.statusCounts.entrySet()) {
                totalStatusCounts.merge(entry.getKey(), entry.getValue(), Integer::sum);
            }

            allResponseTimes.addAll(result.responseTimes);
        }

        long successfulRequests = totalRequests - totalFailures;
        double executionTime = duration / 1000.0;
        double throughput = executionTime > 0 ? totalRequests / executionTime : 0;

        // Calculate response time statistics
        long minTime = 0, maxTime = 0, avgTime = 0, p50Time = 0, p95Time = 0, p99Time = 0;
        if (!allResponseTimes.isEmpty()) {
            Collections.sort(allResponseTimes);
            minTime = allResponseTimes.get(0);
            maxTime = allResponseTimes.get(allResponseTimes.size() - 1);
            avgTime = allResponseTimes.stream().mapToLong(Long::longValue).sum() / allResponseTimes.size();
            p50Time = allResponseTimes.get(allResponseTimes.size() / 2);
            p95Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.95));
            p99Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.99));
        }

        // Get status counts
        int goodCount = totalStatusCounts.getOrDefault("GOOD", 0);
        int revokedCount = totalStatusCounts.getOrDefault("REVOKED", 0);
        int unknownCount = totalStatusCounts.getOrDefault("UNKNOWN", 0);

        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(filename)))) {
            // Write header
            writer.println("Test Duration (s),Total Requests,Successful,Failed,Throughput (req/s),Min Response (ms),Max Response (ms),Avg Response (ms),P50 (ms),P95 (ms),P99 (ms),GOOD,REVOKED,UNKNOWN,Timestamp");

            // Write data row
            String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());
            writer.println(String.format("%.2f,%d,%d,%d,%.2f,%d,%d,%d,%d,%d,%d,%d,%d,%d,%s",
                    executionTime, totalRequests, successfulRequests, totalFailures, throughput,
                    minTime, maxTime, avgTime, p50Time, p95Time, p99Time,
                    goodCount, revokedCount, unknownCount, timestamp));
        }
    }

    /**
     * Write test results to Markdown file
     */
    private void writeResultsToMarkdown(String filename, List<OcspTestResult> results, long duration) throws IOException {
        // Aggregate counts
        long totalRequests = 0;
        long totalFailures = 0;
        Map<String, Integer> totalStatusCounts = new HashMap<>();
        List<Long> allResponseTimes = new ArrayList<>();

        for (OcspTestResult result : results) {
            totalRequests += result.responseTimes.size() + result.failures.size();
            totalFailures += result.failures.size();

            for (Map.Entry<String, Integer> entry : result.statusCounts.entrySet()) {
                totalStatusCounts.merge(entry.getKey(), entry.getValue(), Integer::sum);
            }

            allResponseTimes.addAll(result.responseTimes);
        }

        long successfulRequests = totalRequests - totalFailures;
        double executionTime = duration / 1000.0;
        double throughput = executionTime > 0 ? totalRequests / executionTime : 0;

        // Calculate response time statistics
        long minTime = 0, maxTime = 0, avgTime = 0, p50Time = 0, p95Time = 0, p99Time = 0;
        if (!allResponseTimes.isEmpty()) {
            Collections.sort(allResponseTimes);
            minTime = allResponseTimes.get(0);
            maxTime = allResponseTimes.get(allResponseTimes.size() - 1);
            avgTime = allResponseTimes.stream().mapToLong(Long::longValue).sum() / allResponseTimes.size();
            p50Time = allResponseTimes.get(allResponseTimes.size() / 2);
            p95Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.95));
            p99Time = allResponseTimes.get((int) (allResponseTimes.size() * 0.99));
        }

        // Get status counts
        int goodCount = totalStatusCounts.getOrDefault("GOOD", 0);
        int revokedCount = totalStatusCounts.getOrDefault("REVOKED", 0);
        int unknownCount = totalStatusCounts.getOrDefault("UNKNOWN", 0);

        String timestamp = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());

        try (PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(filename)))) {
            writer.println("# OCSP Stress Test Results");
            writer.println();
            writer.println("**Generated:** " + timestamp);
            writer.println();

            // Test Configuration section
            writer.println("## Test Configuration");
            writer.println();
            writer.println("| Metric | Value |");
            writer.println("|--------|-------|");
            writer.println(String.format("| Test Duration | %.2f seconds |", executionTime));
            writer.println();

            // Performance Metrics table
            writer.println("## Performance Metrics");
            writer.println();
            writer.println("| Metric | Value |");
            writer.println("|--------|-------|");
            writer.println(String.format("| Total Requests | %,d |", totalRequests));
            writer.println(String.format("| Successful Requests | %,d |", successfulRequests));
            writer.println(String.format("| Failed Requests | %,d |", totalFailures));
            writer.println(String.format("| Throughput | %.2f req/s |", throughput));
            writer.println();

            // Response Times table
            writer.println("## Response Times");
            writer.println();
            writer.println("| Percentile | Response Time (ms) |");
            writer.println("|------------|-------------------|");
            writer.println(String.format("| Minimum | %d |", minTime));
            writer.println(String.format("| Average | %d |", avgTime));
            writer.println(String.format("| P50 (Median) | %d |", p50Time));
            writer.println(String.format("| P95 | %d |", p95Time));
            writer.println(String.format("| P99 | %d |", p99Time));
            writer.println(String.format("| Maximum | %d |", maxTime));
            writer.println();

            // Certificate Status table
            writer.println("## Certificate Status Distribution");
            writer.println();
            writer.println("| Status | Count |");
            writer.println("|--------|-------|");
            writer.println(String.format("| GOOD | %,d |", goodCount));
            writer.println(String.format("| REVOKED | %,d |", revokedCount));
            writer.println(String.format("| UNKNOWN | %,d |", unknownCount));
            writer.println();
        }
    }

    @Override
    public String getMainCommand() {
        return "ocspstress";
    }

    @Override
    public String getCommandDescription() {
        return "Performs multi-threaded OCSP stress testing against an OCSP responder";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "\n\nSupports both POST and GET request types. Serial number file can be either:\n"
                + "  - Simple list: one serial number per line (decimal or hex with 0x prefix)\n"
                + "  - Pipe-delimited: serialNumber|issuerDn (from --savecerts flag)\n\n";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
