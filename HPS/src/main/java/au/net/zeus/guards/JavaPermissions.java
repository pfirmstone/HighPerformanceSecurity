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
package au.net.zeus.guards;

import java.security.Provider;

/**
 *
 * @author peter
 */
public class JavaPermissions extends Provider {
    
    private static boolean checkSecurityManager(){
        if (System.getSecurityManager() != null) throw new
            IllegalStateException("SecurityManager is not allowed to be set");
        return true;
    }
    
    public JavaPermissions(){
        this(checkSecurityManager());
    }
    
    JavaPermissions(boolean check){
        super("java.security.Permission", 1.0, "Guards");
        put("Guards.AWT", "au.net.zeus.guards.AWT");
        put("Guards.FILE", "au.net.zeus.guards.FILE");
        put("Guards.SERIALIZABLE", "au.net.zeus.guards.SERIALIZABLE");
        put("Guards.MANAGEMENT", "au.net.zeus.guards.MANAGEMENT");
        put("Guards.REFLECT", "au.net.zeus.guards.REFLECT");
        put("Guards.NET", "au.net.zeus.guards.NET");
        put("Guards.SOCKET", "au.net.zeus.guards.SOCKET");
        put("Guards.URL", "au.net.zeus.guards.URL");
        put("Guards.LINK", "au.net.zeus.guards.LINK");
        put("Guards.SECURITY", "au.net.zeus.guards.SECURITY");
        put("Guards.SQL", "au.net.zeus.guards.SQL");
        put("Guards.LOGGING", "au.net.zeus.guards.LOGGING");
        put("Guards.PROPERTY", "au.net.zeus.guards.PROPERTY");
        put("Guards.MBEAN", "au.net.zeus.guards.MBEAN");
        put("Guards.MBEAN_SERVER", "au.net.zeus.guards.MBEAN_SERVER");
        put("Guards.MBEAN_TRUST", "au.net.zeus.guards.MBEAN_TRUST");
        put("Guards.SUBJECT_DELEGATION", "au.net.zeus.guards.SUBJECT_DELEGATION");
        put("Guards.TLS", "au.net.zeus.guards.TLS");
        put("Guards.AUTH", "au.net.zeus.guards.AUTH");
        put("Guards.DELEGATION", "au.net.zeus.guards.DELEGATION");
        put("Guards.SERVICE", "au.net.zeus.guards.SERVICE");
        put("Guards.PRIVATE_CREDENTIAL", "au.net.zeus.guards.PRIVATE_CREDENTIAL");
        put("Guards.AUDIO", "au.net.zeus.guards.AUDIO");
        put("Guards.JAXB", "au.net.zeus.guards.JAXB");
        put("Guards.WEB_SERVICE", "au.net.zeus.guards.WEB_SERVICE");
    }
    
    @Override
    public final Object put(Object key, Object value){
        return super.put(key, value);
    }
}