// OpenBack App Auth for Java: the client + token verifier library and the Spring Boot 3 starter.
// Build and test:   ./gradlew build
// Local Maven repo: ./gradlew publishToMavenLocal      (nothing is published to a remote registry from here)

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")

    group = "io.openback"
    version = "1.0.0"

    repositories {
        mavenCentral()
    }

    extensions.configure<JavaPluginExtension> {
        withSourcesJar()
        withJavadocJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf("-Xlint:unchecked", "-Xlint:deprecation"))
    }

    tasks.withType<Javadoc>().configureEach {
        (options as StandardJavadocDocletOptions).apply {
            encoding = "UTF-8"
            addStringOption("Xdoclint:none", "-quiet")
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }

    extensions.configure<PublishingExtension> {
        publications {
            create<MavenPublication>("maven") {
                from(components["java"])
                versionMapping {
                    usage("java-api") { fromResolutionOf("runtimeClasspath") }
                    usage("java-runtime") { fromResolutionResult() }
                }
                pom {
                    name.set(project.name)
                    description.set(provider { project.description })
                    url.set("https://github.com/GexyLab/openback-plugins-community/tree/main/SDK/Auth/java/1.0.0")
                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://opensource.org/licenses/MIT")
                        }
                    }
                    developers {
                        developer {
                            id.set("gexylab")
                            name.set("GexyLab")
                        }
                    }
                    scm {
                        url.set("https://github.com/GexyLab/openback-plugins-community")
                        connection.set("scm:git:https://github.com/GexyLab/openback-plugins-community.git")
                        developerConnection.set("scm:git:ssh://git@github.com/GexyLab/openback-plugins-community.git")
                    }
                }
            }
        }
    }
}
