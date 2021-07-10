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

import au.net.zeus.auth.GuardsSpi;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Guard;
import java.security.Permission;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author peter
 */
public abstract class AbstractGuards extends GuardsSpi {
    
    private static Constructor<? extends Permission> constructor(Class<? extends Permission> permClass) throws NoSuchMethodException{
        return permClass.getConstructor(new Class []{String.class, String.class});
    }

    private final Constructor<? extends Permission> constructor;
    
    protected AbstractGuards(Class<? extends Permission> permClass) throws NoSuchMethodException {
        this(constructor(permClass));
    }
    
    private AbstractGuards(Constructor<? extends Permission> constructor){
        this.constructor = constructor;
    }
    
    @Override
    public Guard post(String target, String actions) {
        try {
            return new PermissionDecorator(constructor.newInstance(new Object[] {target, actions}));
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException ex) {
            Logger.getLogger(getClass().getName()).log(Level.FINE, null, ex);
        } catch (InvocationTargetException ex) {
            Logger.getLogger(getClass().getName()).log(Level.FINE, null, ex);
            Throwable cause = ex.getCause();
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
        }
        return (Object object) -> {};
    }
}
