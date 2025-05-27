
plugins {
    `java-library`
}

repositories {

    maven {
        url = uri("https://repo.maven.apache.org/maven2/")
    }
    
    flatDir { 
        dirs(rootProject.projectDir.resolve("lib")) 
    }
}

dependencies {
    api(libs.com.googlecode.json.simple.json.simple)
    api(libs.org.bouncycastle.bcprov.jdk18on)
    api(libs.org.bouncycastle.bcutil.jdk18on)
    api(libs.org.bouncycastle.bcpkix.jdk18on)
    api(libs.commons.io.commons.io)
    api(libs.org.apache.httpcomponents.httpclient)
    api(libs.org.apache.logging.log4j.log4j.core)
    api(libs.org.apache.logging.log4j.log4j.v1.v2.api)
    api(libs.org.apache.commons.commons.lang3)
    api(libs.commons.lang.commons.lang)
    api(libs.org.codehaus.mojo.exec.maven.plugin)
    api(libs.org.jboss.resteasy.resteasy.client)
    api(libs.jakarta.ws.rs.jakarta.ws.rs.api)
    api(libs.com.keyfactor.keyfactor.commons.cli)
    api(libs.com.keyfactor.x509.common.util)
    api(libs.com.fasterxml.jackson.core)
}

tasks.register<Copy>("copyDependencies") {
    from(configurations.runtimeClasspath.get().filter { it.name.endsWith(".jar") }) {
        duplicatesStrategy = DuplicatesStrategy.EXCLUDE // Options: EXCLUDE, INCLUDE, or WARN
    }
    into(layout.buildDirectory.dir("lib"))
}

tasks.build {
    dependsOn("copyDependencies")
}

tasks.register("cli") {
    group = "Application"
    description = "Run the EJBCA CLI with arguments."
    println("Hello")
}

tasks.jar {
    // Specify the directory where the JAR file will be created
    destinationDirectory.set(layout.buildDirectory)
    
     manifest {
        attributes["Main-Class"] = "com.keyfactor.ejbca.client.ErceClient"        
        val classPathEntries = configurations.runtimeClasspath.get().map { 
            "lib/${it.name}" // Prefix each entry with "lib/"
        }
        attributes("Class-Path" to classPathEntries.joinToString(" "))
    }
}

group = "com.keyfactor"
version = "1.7.0"
description = "Easy REST Client for EJBCA"
java.sourceCompatibility = JavaVersion.VERSION_17


sourceSets {
    main {
        java {
            setSrcDirs(listOf("src"))
        }
    }
    test {
        java {
            setSrcDirs(listOf("src-test"))
        }
    }
}


