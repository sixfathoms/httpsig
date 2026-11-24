import com.vanniktech.maven.publish.MavenPublishBaseExtension

plugins {
    java
    alias(libs.plugins.maven.publish) apply false
}

subprojects {
    apply(plugin = "java-library")

    java {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    repositories {
        mavenCentral()
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }

    // Maven Central requires a javadoc jar, so catch javadoc errors before a release.
    tasks.named("check") {
        dependsOn("javadoc")
    }
}

// Set by the release workflow from the tag.
val releaseVersion = providers.gradleProperty("releaseVersion").getOrElse("0.0.0-SNAPSHOT")

subprojects {
    plugins.withId("com.vanniktech.maven.publish") {
        configure<MavenPublishBaseExtension> {
            publishToMavenCentral(automaticRelease = true)
            signAllPublications()
            coordinates("dev.sixfathoms", project.property("artifactId") as String, releaseVersion)
            pom {
                name.set(project.property("artifactId") as String)
                description.set("HTTP Message Signatures (RFC 9421) for Java")
                url.set("https://github.com/sixfathoms/httpsig")
                inceptionYear.set("2026")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("sixfathoms")
                        name.set("Six Fathoms")
                        url.set("https://github.com/sixfathoms")
                    }
                }
                scm {
                    url.set("https://github.com/sixfathoms/httpsig")
                    connection.set("scm:git:https://github.com/sixfathoms/httpsig.git")
                    developerConnection.set("scm:git:ssh://git@github.com/sixfathoms/httpsig.git")
                }
            }
        }
    }
}
