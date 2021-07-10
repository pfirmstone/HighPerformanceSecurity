/*
 * Copyright 2021 peter.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package au.net.zeus.auth;

import java.security.Guard;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author peter
 */
public class Guards {

    public static Guards unit(String responsibility) {
        Set<String> algorithms = Security.getAlgorithms("Guards");
        if (algorithms.contains(responsibility)){
            Provider [] providers = Security.getProviders("Guards." + responsibility);
            for (int i = 0, l = providers.length; i < l; i++){
                Service s = providers[i].getService("Guards", responsibility);
                try {
                    GuardsSpi spi = (GuardsSpi) s.newInstance(null);
                    return new Guards(spi, responsibility, providers[i]);
                } catch (NoSuchAlgorithmException ex) {
                    Logger.getLogger(Guards.class.getName()).log(Level.CONFIG, null, ex);
                }
            }
        }
        return new Guards(responsibility);
    }
    
    public static Guards unit(String responsibility, String provider){
        return unit(responsibility, Security.getProvider(provider));
    }
    
    public static Guards unit(String responsibility, Provider provider){
        if (responsibility == null) throw new IllegalArgumentException("responsibility cannot be null");
        if (provider == null) throw new IllegalArgumentException("provider cannot be null");
        Service s = provider.getService("Guards", responsibility);
        try {
            GuardsSpi spi = (GuardsSpi) s.newInstance(null);
            return new Guards(spi, responsibility, provider);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Guards.class.getName()).log(Level.CONFIG, "Missing Guard implementation, returning no operation Guard", ex);
        }
        return new Guards(responsibility);
    }
    
    private final GuardsSpi spi;
    private final String responsibility;
    private final Provider provider;
    
    private Guards(GuardsSpi spi, String responsibility, Provider provider){
        this.spi = spi;
        this.responsibility = responsibility;
        this.provider = provider;
    }
    
    private Guards(String responsibility){
        this.spi = new GuardsSpi(){
            @Override
            public Guard post(String target, String actions) {
                return (Object object) -> {};
            }
        };
        this.responsibility = responsibility;
        this.provider = null;
    }

    public Guard post(String target, String actions) {
        return spi.post(target, actions);
    }
    
    public Guard post(String target) {
        return spi.post(target, null);
    }
    
    public Provider getProvider(){
        return provider;
    }
    
    public String getResponsibility(){
        return responsibility;
    }
    
}
