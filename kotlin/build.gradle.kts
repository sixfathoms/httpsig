import com.vanniktech.maven.publish.MavenPublishBaseExtension

plugins {
    kotlin("jvm") version libs.versions.kotlin apply false
    alias(libs.plugins.maven.publish) apply false
}

subprojects {
    repositories {
        mavenCentral()
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
                description.set("HTTP Message Signatures (RFC 9421) for Kotlin")
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
