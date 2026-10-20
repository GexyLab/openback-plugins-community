description = "Spring Boot 3 auto-configuration for OpenBack App Auth: verifies the pool's access tokens and exposes an Authentication with ROLE_ and PERM_ authorities."

val springBootVersion = "3.3.5"

dependencies {
    api(project(":openback-app-auth-java"))
    implementation(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
    api("org.springframework.boot:spring-boot-autoconfigure")
    api("org.springframework.security:spring-security-config")
    api("org.springframework.security:spring-security-web")
    compileOnly("jakarta.servlet:jakarta.servlet-api")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor:$springBootVersion")

    testImplementation(platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion"))
    testImplementation("org.springframework.boot:spring-boot-starter-web")
    testImplementation("org.springframework.boot:spring-boot-starter-security")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

tasks.jar {
    manifest {
        attributes(
            "Automatic-Module-Name" to "io.openback.appauth.spring",
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
        )
    }
}
