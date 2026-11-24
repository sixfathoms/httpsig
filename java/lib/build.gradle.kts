plugins {
    `java-library`
    alias(libs.plugins.maven.publish)
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(libs.jackson.databind)
}
