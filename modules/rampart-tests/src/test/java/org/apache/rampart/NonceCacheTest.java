/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rampart;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by IntelliJ IDEA.
 * User: aj
 * Date: Apr 30, 2010
 * Time: 4:15:20 PM
 * To change this template use File | Settings | File Templates.
 */
public class NonceCacheTest {

  @Test
  public void testAddToCache() throws Exception {

    UniqueMessageAttributeCache cache = new NonceCache();

    cache.addToCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
    cache.addToCache("j8EqKYJ/CxOdfN8CySMm0g==", "apache");
    cache.addToCache("j8EqKYJ/CxOhfN8CySMm0g==", "apache");
  }

  @Test
  public void testValueExistsInCache() throws Exception{

    UniqueMessageAttributeCache cache = new NonceCache();

    cache.addToCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
    cache.addToCache("j8EqKYJ/CxOdfN8CySMm0g==", "apache");
    cache.addToCache("j8EqKYJ/CxOhfN8CySMm0g==", "apache");

    boolean returnValue1 = cache.valueExistsInCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
    assertTrue(returnValue1, "nonce - j8EqKYJ/CxOZfN8CySMm0g== and apache must exists in the cache");

    boolean returnValue2 = cache.valueExistsInCache("p8EqKYJ/CxOZfN8CySMm0g==", "apache");
    assertFalse(returnValue2, "nonce - p8EqKYJ/CxOZfN8CySMm0g== and apache should not be in the cache");
  }

  @Test
  public void testValueExpiration() throws Exception{

    UniqueMessageAttributeCache cache = new NonceCache();

    cache.addToCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
    cache.addToCache("j8EqKYJ/CxOdfN8CySMm0p==", "apache");
    cache.addToCache("q8EqKYJ/CxOhfN8CySMm0g==", "apache");

    cache.setMaximumLifeTimeOfAnAttribute(1);

    assertTrue(cache.valueExistsInCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache"),
               "nonce - j8EqKYJ/CxOZfN8CySMm0g== and apache must exists in the cache");

    Thread.sleep(2 * 1000);

    assertFalse(cache.valueExistsInCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache"),
                "nonce - j8EqKYJ/CxOZfN8CySMm0g== and apache must not exists in the cache");

  }

}
