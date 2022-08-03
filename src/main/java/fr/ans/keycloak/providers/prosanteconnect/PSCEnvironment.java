package fr.ans.keycloak.providers.prosanteconnect;

import java.util.Properties;

enum PSCEnvironment {

  INTEGRATION("psc.bas"),
  PRODUCTION("psc.prod");

  static final String ENVIRONMENT_PROPERTY_NAME = "psc_environment";
  private static final Properties PROPERTIES = Utils.loadProperties("psc.properties");

  private final String propertyPrefix;

  PSCEnvironment(String propertyPrefix) {
    this.propertyPrefix = propertyPrefix;
  }

  public String getProperty(String key) {
    return PROPERTIES.getProperty(propertyPrefix + "." + key);
  }

  static PSCEnvironment getOrDefault(String environmentName, PSCEnvironment defaultEnvironment) {
    for (var environment : PSCEnvironment.values()) {
      if (environment.name().equalsIgnoreCase(environmentName)) {
        return environment;
      }
    }

    return defaultEnvironment;
  }
}
