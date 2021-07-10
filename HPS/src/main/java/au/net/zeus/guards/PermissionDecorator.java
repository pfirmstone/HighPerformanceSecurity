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

import au.net.zeus.auth.Authorization;
import au.net.zeus.auth.AuthorizationException;
import au.net.zeus.hps.ConcurrentPolicyFile;
import au.net.zeus.hps.PolicyInitializationException;
import au.net.zeus.hps.ScalableNestedPolicy;
import java.security.Guard;
import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author peter
 */
class PermissionDecorator implements Guard {
    
    private static final ScalableNestedPolicy POLICY;
    
    static {
        ScalableNestedPolicy policy;
        try {
            policy = new ConcurrentPolicyFile();
        } catch (PolicyInitializationException ex) {
            policy = (ProtectionDomain domain) -> Collections.emptyList();
            Logger.getLogger(PermissionDecorator.class.getName()).log(Level.SEVERE, "Using policy which grants all access", ex);
        } 
        POLICY = policy;
    }

    private final Permission permission;
    
    PermissionDecorator(Permission p){
        this.permission = p;
    }

    @Override
    public final void checkGuard(Object object) throws SecurityException {
        Authorization auth = Authorization.getAuthorization();
        auth.checkEach((ProtectionDomain t) -> {
            if (!POLICY.implies(t, permission)) {
                StringBuilder sb = new StringBuilder();
                sb.append("ProtectionDomain: ").append(t)
                        .append(" failed permission check ")
                        .append(permission).append('\n')
                        .append("PermissionGrant's:\n")
                        .append(POLICY.getPermissionGrants(t));
                throw new AuthorizationException(sb.toString());
            }
        });
    }
    
}
