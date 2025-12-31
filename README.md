# Erce – The Easy Rest Client for EJBCA 
[![Discuss](https://img.shields.io/badge/discuss-ejbca-ce?style=flat)](https://github.com/Keyfactor/ejbca-ce/discussions) 

Erce is a fully FOSS REST Client for EJBCA. Its purpose is to act as a REST-based alternative to the EJBCA CLI and other enrollment protocols such as SCEP and CMP in environments where the UI is not available/optimal, but also to allow for further scripting by branching and extending this implementation. Erce is compatible with EJBCA 7.9.0.1 and later, though the latest released version is recommended for full endpoint support. 

Erce contains support for both CE and EE endpoints, as well as a built in stress test to measure performance and throughput. 

## Get started 

Erce is a fully self-contained Gradle project. To build:

1. Check out a local branch 
2. Build and package using Gradle
```
./gradlew build
```
3. Run the resulting .jar file with the --help flag to see the available commands. 

```
java -jar build/erce-x.y.x.jar --help
```
An example command can looks like:

```
java -jar build/erce-1.0.0.jar enroll genkeys --authkeystore /opt/ejbca/p12/superadmin.p12 --authkeystorepass ****  --endentityprofile "Server" --certificateprofile "Server" --ca ServerCA --subjectaltname "dnsName=test-erces-01.test"  --hostname localhost --destination ./certs --subjectdn "C=SE,O=Keyfactor Community,CN=test-erces-01.test" --username test-erces-01.test -p --keyalg EC --keyspec P-256 --verbose
```

## Supported Endpoints
- /v1/ca_management
  - /v1/ca_management/{ca_name}/deactivate
  - /v1/ca_management/{ca_name}/activate
- v1/ca
  - v1/ca/{subject_dn}/certificate/download
  - v1/ca/{issuer_dn}/getLatestCrl
  - /v1/ca/{issuer_dn}/createcrl
- v1/certificate
  - v1/certificate/pkcs10enroll
  - v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke
- v2/certificate
  - v2/certificate/status
  - v2/certificate/count
- v1/configdump
 
### Additional Commands

#### X509 Stress Test

The X509 stress test command performs multi-threaded certificate issuance testing against EJBCA to measure performance and throughput.

**Basic Usage:**
```bash
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --ca "MyCA" \
  --certificateprofile "ENDUSER" \
  --endentityprofile "MyProfile" \
  --threads 10 \
  --certs 100
```

**Advanced Features:**

*Custom Subject DN and SAN:*
```bash
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --ca "MyCA" \
  --certificateprofile "ENDUSER" \
  --endentityprofile "MyProfile" \
  --threads 5 \
  --certs 50 \
  --subjectdn "CN=User,OU=Engineering,O=Keyfactor,C=US" \
  --san "dnsName=user.example.com,ipAddress=10.0.0.1"
```

*Certificate History Testing (multiple certs per entity):*
```bash
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --ca "MyCA" \
  --certificateprofile "ENDUSER" \
  --endentityprofile "MyProfile" \
  --threads 10 \
  --certs 100 \
  --history 2
```

*Revocation Testing:*
```bash
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --ca "MyCA" \
  --certificateprofile "ENDUSER" \
  --endentityprofile "MyProfile" \
  --threads 10 \
  --certs 100 \
  --revoke \
  --savecerts issued_certs.txt
```

*Bulk Revocation from File:*
```bash
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --revokefile issued_certs.txt \
  --threads 10
```

*Progress Tracking and CSV Output:*
```bash
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --ca "MyCA" \
  --certificateprofile "ENDUSER" \
  --endentityprofile "MyProfile" \
  --threads 10 \
  --certs 100 \
  --progressinterval 5 \
  --outputformat csv \
  --outputfile results.csv
```

#### OCSP Stress Test

The OCSP stress test command performs multi-threaded OCSP status lookups to test OCSP responder performance.

**Basic Usage:**
```bash
java -jar build/erce-1.9.0.jar ocspstress \
  --ocspurl "http://ejbca.example.com:8080/ejbca/publicweb/status/ocsp" \
  --ocspsnfile serial_numbers.txt \
  --cacertfile ca.pem \
  --threads 10 \
  --waittime 50
```

**Serial Number File Formats:**

Simple format (one serial per line):
```
12345678
0xABCDEF123456
987654321
```

Or use the pipe-delimited format from `--savecerts`:
```
1A2B3C4D5E6F|CN=Test CA,O=Keyfactor,C=US
7G8H9I0J1K2L|CN=Test CA,O=Keyfactor,C=US
```

**Advanced Features:**

*Time-Limited Test with Random Wait:*
```bash
java -jar build/erce-1.9.0.jar ocspstress \
  --ocspurl "http://ejbca.example.com:8080/ocsp" \
  --ocspsnfile serial_numbers.txt \
  --cacertfile ca.pem \
  --threads 20 \
  --waittime 100 \
  --duration 300 \
  --randomwait
```

*GET Requests (instead of POST):*
```bash
java -jar build/erce-1.9.0.jar ocspstress \
  --ocspurl "http://ejbca.example.com:8080/ocsp" \
  --ocspsnfile serial_numbers.txt \
  --cacertfile ca.pem \
  --threads 5 \
  --waittime 100 \
  --reqtype GET
```

*Save Debug Requests and Responses:*
```bash
java -jar build/erce-1.9.0.jar ocspstress \
  --ocspurl "http://ejbca.example.com:8080/ocsp" \
  --ocspsnfile serial_numbers.txt \
  --cacertfile ca.pem \
  --threads 5 \
  --waittime 100 \
  --saveocsp /tmp/ocsp-debug
```

*Progress Tracking and Markdown Output:*
```bash
java -jar build/erce-1.9.0.jar ocspstress \
  --ocspurl "http://ejbca.example.com:8080/ocsp" \
  --ocspsnfile serial_numbers.txt \
  --cacertfile ca.pem \
  --threads 10 \
  --waittime 50 \
  --duration 60 \
  --progressinterval 5 \
  --outputformat markdown \
  --outputfile results.md
```

**Integrated Workflow (X509 + OCSP):**
```bash
# Step 1: Issue certificates and save for OCSP testing
java -jar build/erce-1.9.0.jar stress \
  --authkeystore /path/to/admin.p12 \
  --authkeystorepass password \
  --hostname ejbca.example.com:8443 \
  --ca "MyCA" \
  --certificateprofile "ENDUSER" \
  --endentityprofile "MyProfile" \
  --threads 10 \
  --certs 100 \
  --savecerts issued_certs.txt

# Step 2: Run OCSP stress test on issued certificates
java -jar build/erce-1.9.0.jar ocspstress \
  --ocspurl "http://ejbca.example.com:8080/ocsp" \
  --ocspsnfile issued_certs.txt \
  --cacertfile myca.pem \
  --threads 10 \
  --waittime 50
```

## Community Support
In the [Keyfactor Community](https://www.keyfactor.com/community/), we welcome contributions. 

The Community software is open-source and community-supported, meaning that **no SLA** is applicable.

* To report a problem or suggest a new feature, go to [Issues](../../issues).
* If you want to contribute actual bug fixes or proposed enhancements, see the [Contributing Guidelines](CONTRIBUTING.md) and go to [Pull requests](../../pulls).

## Commercial Support

Commercial support is available for [EJBCA Enterprise](https://www.keyfactor.com/products/ejbca-enterprise/).

## License
For license information, see [LICENSE](LICENSE). 

## Related Projects
### On GitHub
See all [Keyfactor EJBCA GitHub projects](https://github.com/orgs/Keyfactor/repositories?q=ejbca). 

### On DockerHub
See the [EJBCA container on DockerHub](https://hub.docker.com/r/keyfactor/ejbca-ce).
