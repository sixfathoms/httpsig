plugins {
    `java-library`
    alias(libs.plugins.maven.publish)
}

dependencies {
    api(project(":lib"))

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
