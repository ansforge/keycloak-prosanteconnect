/*
 * MIT License
 *
 * Copyright (c) 2022-2023 Agence du Numérique en Santé
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
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
