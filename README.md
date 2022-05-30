# Erce – The Easy Rest Client for EJBCA

Erce is a fully FOSS REST Client for EJBCA Community Edition. Its purpose is to act as a REST-based alterative to the EJBCA CLI and other enrollment protocols such as SCEP and CMP in environments where the UI is not available/optimal, but also to allow for further scripting by branching and extending this implementation. Erce is compatible with EJBCA 7.9.0.1 and later. 

## Get started 

Erce is a fully self contained Maven project. To build:

1. Check out a local branch 
2. Build and package using Maven:
```
mvn clean package
```
3. Run the resulting .jar file with the --help flag to see the available commands. 

## Community Support

In our Community we welcome contributions. The Community software is open source and community supported, there is no support SLA, but a helpful best-effort Community.

* To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. 
* If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## License
EJBCA Community is licensed under the LGPL license, please see **[LICENSE](LICENSE)**.

## Related projects 

* [Keyfactor/ansible-ejbca-signserver-playbooks](https://github.com/Keyfactor/ansible-ejbca-signserver-playbooks) 
* [Keyfactor/ejbca-tools](https://github.com/Keyfactor/ejbca-tools) 
* [Keyfactor/ejbca-containers](https://github.com/Keyfactor/ejbca-containers) 
