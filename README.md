# Erce – The Easy Rest Client for EJBCA [![Discuss](https://img.shields.io/badge/discuss-ejbca-ce?style=flat)](https://github.com/Keyfactor/ejbca-ce/discussions) 

Erce is a fully FOSS REST Client for EJBCA Community Edition. Its purpose is to act as a REST-based alterative to the EJBCA CLI and other enrollment protocols such as SCEP and CMP in environments where the UI is not available/optimal, but also to allow for further scripting by branching and extending this implementation. Erce is compatible with EJBCA 7.9.0.1 and later. 

## Get started 

Erce is a fully self contained Maven project. To build:

1. Check out a local branch 
2. Build and package using Maven:
```
mvn clean package
```
3. Run the resulting .jar file with the --help flag to see the available commands. 

```
java -jar target/erce-x.y.x-SNAPSHOT.jar --help
```
An example command can looks like:

```
java -jar target/erce-0.0.8-SNAPSHOT.jar enroll genkeys --authkeystore /opt/ejbca/p12/superadmin.p12 --authkeystorepass ****  --endentityprofile "Server" --certificateprofile "Server" --ca ServerCA --subjectaltname "dnsName=test-erces-01.test"  --hostname localhost --destination ./certs --subjectdn "C=SE,O=Keyfactor Community,CN=test-erces-01.test" --username test-erces-01.test -p --keyalg EC --keyspec P-256 --verbose
```

## Community Support

In our Community we welcome contributions. The Community software is open source and community supported, there is no support SLA, but a helpful best-effort Community.

* To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. 
* If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.
* Ask the community for ideas: **[EJBCA Discussions](https://github.com/Keyfactor/ejbca-ce/discussions)**.  

## License
Erce is licensed under the LGPL license, please see **[LICENSE](LICENSE)**.

## Related projects 

### On GitHub
* [Keyfactor/ejbca-ce](https://github.com/Keyfactor/ejbca-ce) 
* [Keyfactor/ansible-ejbca-signserver-playbooks](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks) 
* [Keyfactor/ejbca-tools](https://github.com/Keyfactor/ejbca-tools) 
* [Keyfactor/ejbca-containers](https://github.com/Keyfactor/ejbca-containers) 

### On DockerHub
* [EJBCA container on DockerHub](https://hub.docker.com/r/keyfactor/ejbca-ce) 
