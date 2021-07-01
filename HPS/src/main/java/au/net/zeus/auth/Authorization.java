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

import java.io.ObjectStreamException;
import java.lang.StackWalker.Option;
import java.lang.StackWalker.StackFrame;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.security.Guard;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.security.auth.Subject;
import org.apache.river.api.net.Uri;
import org.apache.river.concurrent.RC;
import org.apache.river.concurrent.Ref;

/**
 * Authorization class, instances contain the domains and Subject of the
 * Authorization context, used for Authorization decisions by Guard 
 * implementations.  Provides static utility methods to make privilgedCall's
 * and record the current context.
 * 
 * @author peter
 */
public final class Authorization {
    
    private static final ProtectionDomain MY_DOMAIN = Authorization.class.getProtectionDomain();
    
    private static final Authorization PRIVILEGED = 
            new Authorization(new ProtectionDomain []{ MY_DOMAIN });
    
    private static final Authorization UNPRIVILEGED 
        = new Authorization(
            new ProtectionDomain[]{ 
                new ProtectionDomain(
                        new CodeSource(null, (Certificate [])null), null
                )
            }
        );
    
    private static final ThreadLocal<Authorization> INHERITED_CONTEXT 
            = new ThreadLocal();
    
    private static final Guard GUARD_REGISTER_CHECK = 
        GuardBuilder.getInstance("RUNTIME").get("registerGuard", (String) null);
    
    private static final Guard GUARD_SUBJECT = 
        GuardBuilder.getInstance("AUTH").get("getSubjectFromAuthorization", null);
    
    private static final Set<Class<? extends Guard>> GUARDS = 
            RC.set(Collections.newSetFromMap(new ConcurrentHashMap<>()), Ref.WEAK, 0);
    
    
    
    /**
     * Elevates the privileges of the Callable to those granted to the Subject
     * and ProtectionDomain's of the Callable and it's call stack, including the
     * ProtectionDomain of the caller of this method.
     * 
     * @param <V>
     * @param c
     * @return 
     */
    public static <V> Callable<V> privilegedCall(Callable<V> c){
        Authorization authorization = INHERITED_CONTEXT.get();
        try {
            INHERITED_CONTEXT.set(PRIVILEGED);
            if (authorization != null){
                return privilegedCall(authorization.getSubject(), c);
            } else {
                return new CallableWrapper<>(new Authorization(captureCallerDomain(null), null), c);
            }
        } finally {
            INHERITED_CONTEXT.set(authorization);
        }
    }
    
    /**
     * Elevates the privileges of the Callable to those granted to the Subject
     * and ProtectionDomain's of the Callable and it's call stack, including the
     * ProtectionDomain of the caller of this method.
     * 
     * @param <V>
     * @param subject
     * @param c
     * @return 
     */
    public static <V> Callable<V> privilegedCall(Subject subject, Callable<V> c){
        Authorization authorization = INHERITED_CONTEXT.get();
        try {
            INHERITED_CONTEXT.set(PRIVILEGED);
            Set<Principal> p = subject != null ? subject.getPrincipals() : null;
            Principal [] principals = p != null ? p.toArray(new Principal[p.size()]) : null;
            return new CallableWrapper<>(new Authorization(captureCallerDomain(principals), subject), c);
        } finally {
            INHERITED_CONTEXT.set(authorization);
        }
    }
    
    /**
     * Elevates the privileges of the Callable to those granted to the Subject
     * and ProtectionDomain's of the Callable and it's call stack, including the
     * ProtectionDomain of the caller of this method and the Authorization
     * context provided.
     * 
     * @param <V>
     * @param ac
     * @param c
     * @return 
     */
    public static <V> Callable<V> privilegedCall(Authorization ac, Callable<V> c){
        if (c == null) throw new IllegalArgumentException("Callable cannot be null");
        if (ac != null){
            Authorization authorization = INHERITED_CONTEXT.get();
            try {
                INHERITED_CONTEXT.set(PRIVILEGED);
                Subject subject = ac.getSubject();
                Set<Principal> p = subject != null ? subject.getPrincipals() : null;
                Principal [] principals = p != null ? p.toArray(new Principal[p.size()]) : null;
                Set<ProtectionDomain> domains = captureCallerDomain(principals);
                ac.checkEach((ProtectionDomain t) -> {
                    if (MY_DOMAIN.equals(t)) return;
                    if (principals != null){
                        domains.add(
                            new ProtectionDomainKey(t, principals)
                        );
                    } else {
                        domains.add(new ProtectionDomainKey(t));
                    }
                });
                Authorization auth = new Authorization(domains, subject);
                return new CallableWrapper<>(auth, c);
            } finally {
                INHERITED_CONTEXT.set(authorization);
            }
        } else {
            return privilegedCall(c);
        }
    }
    
    private static Set<ProtectionDomain> captureCallerDomain(Principal [] principals){
        Set<Option> options = new HashSet<>();
        options.add(Option.RETAIN_CLASS_REFERENCE);
        StackWalker walker = StackWalker.getInstance(options);
        List<StackFrame> frames = walker.walk(s ->
            s.dropWhile(f -> f.getClassName().equals(Authorization.class.getName()))
             .limit(1L) // Grab the caller who called privilegedCall.
             .collect(Collectors.toList()));
        Set<ProtectionDomain> domains = new HashSet<>();
        Iterator<StackFrame> it = frames.iterator();
        while (it.hasNext()){
            ProtectionDomain t = it.next().getDeclaringClass().getProtectionDomain();
            if (MY_DOMAIN.equals(t)) continue;
            if (principals != null){
                domains.add(new ProtectionDomainKey(t, principals));
            } else {
                domains.add(new ProtectionDomainKey(t));
            }
        }
        return domains;
    }
    
    /**
     * Avoids stack walk, returns an Authorization containing a ProtectionDomain
     * with the Principal [] of the current Subject, if any.  The CodeSource
     * of this domain contains a <code>null</code> URL.  If there is no current
     * Subject, this domain will be unprivileged.
     * 
     * @return 
     */
    public static Authorization getSubjectAuthorization(){
        Authorization authorization = INHERITED_CONTEXT.get();
        if (authorization == null) return UNPRIVILEGED;
        try {
            INHERITED_CONTEXT.set(PRIVILEGED);
            Subject subject = authorization.getSubject();
            Set<Principal> p = subject != null ? subject.getPrincipals() : null;
            Principal [] principals = p != null ? p.toArray(new Principal[p.size()]) : null;
            Set<ProtectionDomain> domains = new HashSet<>(1);
            domains.add(
                new ProtectionDomainKey(
                    new CodeSource(null, (Certificate[]) null),
                    null,
                    null,
                    principals
                )
            );
            return new Authorization(domains, subject);
        } finally {
            INHERITED_CONTEXT.set(authorization);
        }
    }
    
    /**
     * Performs a stack walk to obtain all domains since the {@link Callable#call() }
     * method was made, includes the domain of the caller of any of the three 
     * {@link #privilegedCall(javax.security.auth.Subject, java.util.concurrent.Callable) 
     * methods as well as the {@link Subject}.  All domains on the stack contain the
     * {@link Principal} of the Subject.
     * 
     * If a privilegedCall wasn't made, then an unprivileged Authorization
     * instance is returned.
     * 
     * @return 
     */
    public static Authorization getAuthorization(){
        // Optimise, avoid stack walk if UNPRIVILEGED.
        Authorization authorization = INHERITED_CONTEXT.get();
        if (authorization == null) return UNPRIVILEGED;
        try {
            INHERITED_CONTEXT.set(PRIVILEGED);
            Subject subject = authorization.getSubject();
            Set<Principal> p = subject != null ? subject.getPrincipals() : null;
            Principal [] principals = p != null ? p.toArray(new Principal[p.size()]) : null;
            Set<Option> options = new HashSet<>();
            options.add(Option.RETAIN_CLASS_REFERENCE);
            StackWalker walker = StackWalker.getInstance(options);
            List<StackFrame> frames = walker.walk(s -> 
                s.skip(1) //Skips getAuthorization()
                 .takeWhile(f -> !f.getClassName().equals(CallableWrapper.class.getName())))
                 .collect(Collectors.toList());
            Set<ProtectionDomain> domains = new HashSet<>(frames.size());
            authorization.checkEach((ProtectionDomain t) -> {
                if (MY_DOMAIN.equals(t)) return;
                if (principals != null){
                    domains.add(new ProtectionDomainKey(t, principals));
                } else {
                    domains.add(new ProtectionDomainKey(t));
                }
            });
            Iterator<StackFrame> it = frames.iterator();
            while (it.hasNext()){
                Class declaringClass = it.next().getDeclaringClass();
                ProtectionDomain t = declaringClass.getProtectionDomain();
                if (MY_DOMAIN.equals(t)) continue;
                CodeSource cs = t.getCodeSource();
                if (cs == null){ // Bootstrap ClassLoader?
                    Module module = declaringClass.getModule();
                    if (module.isNamed()){
                        try {
                            cs = new CodeSource( new URL("jrt:/" + module.getName()), (Certificate[]) null);
                        } catch (MalformedURLException ex) {
                            Logger.getLogger(Authorization.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
                if (principals != null){
                    domains.add(new ProtectionDomainKey(cs, t.getPermissions(), t.getClassLoader(), principals));
                } else {
                    domains.add(new ProtectionDomainKey(cs, t.getPermissions(), t.getClassLoader(), t.getPrincipals()));
                }
            }
            return new Authorization(domains, subject);
        } finally {
            INHERITED_CONTEXT.set(authorization);
        }
    }
    
    /**
     * Register the calling Class type for a Guard implementation.
     * 
     * Prior to calling {@link Authorization#checkEach(java.util.function.Consumer) 
     * a guard must register, this should be during initialization the ProtectionDomain
     * of the guard will be checked.  This should occur prior to 
     * 
     * 
     * @param guardClass 
     */
    public static void registerGuard(Class<? extends Guard> guardClass){
        GUARD_REGISTER_CHECK.checkGuard(guardClass);
        GUARDS.add(guardClass);
    }
    
    private final Set<ProtectionDomain> context;
    private final Subject subject;
    private final int hashCode;
    
    private Authorization(Set<ProtectionDomain> context, Subject s) {
        this.context = context;
        this.subject = s;
        int hash = 7;
        hash = 11 * hash + Objects.hashCode(context);
        hash = 11 * hash + Objects.hashCode(s);
        this.hashCode = hash;
    }
    
    private Authorization(ProtectionDomain [] context){
        this(new HashSet<ProtectionDomain>(Arrays.asList(context)), null);
    }
    
    
    public Subject getSubject(){
        if (!PRIVILEGED.equals(INHERITED_CONTEXT.get())) 
            GUARD_SUBJECT.checkGuard(null);
        return subject;
    }
    
    /**
     * 
     * @param consumer
     * @throws AuthorizationException 
     */
    public void checkEach(Consumer<ProtectionDomain> consumer) throws AuthorizationException {
        Authorization authorization = INHERITED_CONTEXT.get();
        if (UNPRIVILEGED.equals(authorization)) throw new AuthorizationException("A privilegedCall is required to enable privileges.");
        if (PRIVILEGED.equals(authorization)) return; // Avoids circular checks.
        try {
            INHERITED_CONTEXT.set(PRIVILEGED);
            Set<Option> options = new HashSet<>();
            options.add(Option.RETAIN_CLASS_REFERENCE);
            StackWalker walker = StackWalker.getInstance(options);
            List<StackFrame> frames = walker.walk(s ->
                s.dropWhile(f -> f.getClassName().equals(Authorization.class.getName()))
                 .limit(1L) // Grab the caller who called privilegedCall.
                 .collect(Collectors.toList()));
            frames.stream().forEach((StackFrame t) -> {
                Class cl = t.getDeclaringClass();
                if (!Guard.class.isAssignableFrom(cl) || !GUARDS.contains(cl)){
                    throw new AuthorizationException("Guard not registered: " + cl.getCanonicalName());
                }
            });
        } finally {
            INHERITED_CONTEXT.set(authorization);
        }
        // The actual check for privileged code.
        context.stream().forEach(consumer);
    }
    
    @Override
    public boolean equals(Object o){
        if (this == o) return true;
        if (!(o instanceof Authorization)) return false;
        Authorization that = (Authorization) o;
        if (!this.subject.equals(that.subject)) return false;
        return this.context.equals(that.context);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }
    
    private static class CallableWrapper<V> implements Callable<V> {
        
        
        private final Authorization authorization;
        private final Callable<V> callable;
        
        CallableWrapper(Authorization a, Callable<V> c){
            this.authorization = a;
            this.callable = c;
        }

        @Override
        public V call() throws Exception {
            Authorization previousContext = INHERITED_CONTEXT.get();
            INHERITED_CONTEXT.set(authorization);
            try {
                return callable.call();
            } finally {
                INHERITED_CONTEXT.set(previousContext);
            }
        }
        
    }
    
    /**
     * ProtectionDomainKey identity .
     */
    private static class ProtectionDomainKey extends ProtectionDomain{
        
        private static UriCodeSource getCodeSource(CodeSource cs){
            if (cs != null) return new UriCodeSource(cs);
            return null;
        }

        private final CodeSource codeSource;
        private final Principal[] princiPals;
        private final int hashCode;

        ProtectionDomainKey(ProtectionDomain pd){
            this(getCodeSource(pd.getCodeSource()), pd.getPermissions(), pd.getClassLoader(), pd.getPrincipals());
        }
        
        ProtectionDomainKey(ProtectionDomain pd, Principal [] p) {
            this(getCodeSource(pd.getCodeSource()), pd.getPermissions(), pd.getClassLoader(), p);
        }
        
        ProtectionDomainKey(CodeSource cs, PermissionCollection perms, ClassLoader cl, Principal [] p){
            this(getCodeSource(cs), perms, cl, p);
        }
        
        private ProtectionDomainKey(UriCodeSource urics, PermissionCollection perms, ClassLoader cl, Principal [] p){
            super(urics, perms, cl, p);
            this.codeSource = urics;
            this.princiPals = p;
            int hash = 7;
            hash = 29 * hash + Objects.hashCode(this.codeSource);
            hash = 29 * hash + Objects.hashCode(cl);
            hash = 29 * hash + Arrays.deepHashCode(this.princiPals);
            this.hashCode = hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (obj == null) return false;
            if (getClass() != obj.getClass()) return false;
            final ProtectionDomainKey other = (ProtectionDomainKey) obj;
            if (!Objects.equals(getClassLoader(), other.getClassLoader())) return false;
            if (!Objects.equals(this.codeSource, other.codeSource)) return false;
            return Arrays.deepEquals(this.princiPals, other.princiPals);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
        
    }
    
    /**
     * To avoid CodeSource equals and hashCode methods.
     * 
     * Shamelessly stolen from RFC3986URLClassLoader
     * 
     * CodeSource uses DNS lookup calls to check location IP addresses are 
     * equal.
     * 
     * This class must not be serialized.
     */
    private static class UriCodeSource extends CodeSource {
        private static final long serialVersionUID = 1L;
        private final Uri uri;
        private final int hashCode;
        
        UriCodeSource(CodeSource cs){
            this(cs.getLocation(), cs.getCertificates());
        }
        
        UriCodeSource(URL url, Certificate [] certs){
            super(url, certs);
            Uri uRi = null;
            if (url != null){
                try {
                    uRi = Uri.urlToUri(url);
                } catch (URISyntaxException ex) { }//Ignore
            }
            this.uri = uRi;
            int hash = 7;
            hash = 23 * hash + (this.uri != null ? this.uri.hashCode() : 0);
            hash = 23 * hash + (certs != null ? Arrays.hashCode(certs) : 0);
            hashCode = hash;
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
        
        @Override
        public boolean equals(Object o){
            if (!(o instanceof UriCodeSource)) return false;
            if (uri == null) return super.equals(o); // In case of URISyntaxException
            UriCodeSource that = (UriCodeSource) o; 
            if ( !uri.equals(that.uri)) return false;
            Certificate [] mine = getCertificates();
            Certificate [] theirs = that.getCertificates();
            return Arrays.equals(mine, theirs);
        }
        
        public Object writeReplace() throws ObjectStreamException {
            return new CodeSource(getLocation(), getCertificates());
        }
       
    }
}
