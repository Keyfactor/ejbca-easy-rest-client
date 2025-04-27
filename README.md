# Erce – The Easy Rest Client for EJBCA 
[![Discuss](https://img.shields.io/badge/discuss-ejbca-ce?style=flat)](https://github.com/Keyfactor/ejbca-ce/discussions) 

Erce is a fully FOSS REST Client for EJBCA Community Edition. Its purpose is to act as a REST-based alternative to the EJBCA CLI and other enrollment protocols such as SCEP and CMP in environments where the UI is not available/optimal, but also to allow for further scripting by branching and extending this implementation. Erce is compatible with EJBCA 7.9.0.1 and later. 

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
 
### Additional Commands
- Stress Test

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

TESTING
