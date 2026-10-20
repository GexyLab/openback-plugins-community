description = "OpenBack App Auth for Java: client of an OpenBack user pool, OIDC helpers and access-token verification (ES256)."

dependencies {
    api("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    // Only for RequireAppUserFilter: provided by the servlet container.
    compileOnly("jakarta.servlet:jakarta.servlet-api:6.0.0")

    testImplementation(platform("org.junit:junit-bom:5.10.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation("jakarta.servlet:jakarta.servlet-api:6.0.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(11)
}

tasks.jar {
    manifest {
        attributes(
            "Automatic-Module-Name" to "io.openback.appauth",
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
        )
    }
}
