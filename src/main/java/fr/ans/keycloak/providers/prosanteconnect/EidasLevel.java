/*
 * MIT License
 *
 * Copyright (c) 2022-2024 Agence du Numérique en Santé
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

public enum EidasLevel {
  EIDAS1;

  public static final String EIDAS_LEVEL_PROPERTY_NAME = "eidas_values";

  @Override
  public String toString() {
    return name().toLowerCase();
  }

  public static EidasLevel getOrDefault(String eidasLevelName, EidasLevel defaultEidasLevel) {
    for (var eidasLevel : EidasLevel.values()) {
      if (eidasLevel.name().equalsIgnoreCase(eidasLevelName)) {
        return eidasLevel;
      }
    }
    
    if (eidasLevelName == null) {
    	return defaultEidasLevel;
    }
    
    return null;
  }
}
