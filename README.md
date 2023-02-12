# HighPerformanceSecurity
## Some good news

OpenJDK appears to be softening on adding *Some* hooks, so we need to focus on the hooks that cannot be easily implemented by Agent's.  This has been retracted.

OpenJDK appears open to giving meaningful jrt:// URL's to Java's system module CodeSource's in ProtectionDomain's, which would allow us to reduce the size of Java's trusted computing base.

The guard providers that replicate Java permissions are not all likely to be supported, and the existing check points may be unsuitable for replication, such that the old set of permissions implementations provided by the Java platform are unlikely to be suitable.

## Unfortunate news regarding Java library support for authorization hooks

Java libraries will not allow check points for an authorization framework.   The suggested use of Agents by OpenJDK to insert these check points after investigation is proving brittle and impractical.   - Update Java 18 onwards, allows finalizers to be disabled, this means that Agent check points will be viable, provided finalizers are disabled.

## Previously:

Note the code in packages au.net.zeus.hps and au.net.zeus.thread are taken from JGDMS to demonstrate the security technologies utilised by that project, so they are more readable and understandable.  This is not intended for production as test code hasn't been copied across.  If you want to use these libraries they can be found on Maven Central by adding the following dependency:

        <dependency>
            <groupId>au.net.zeus.jgdms</groupId>
            <artifactId>jgdms-platform</artifactId>
            <version>${project.version}</version>
        </dependency>

Code in package au.net.zeus.auth is intended to communicate concepts around a new authorization layer, post Java 17.  The package au.net.zeus.guards provides Guards implementations for existing JDK Permission classes.  An agents package will be provided in the near future, for instrumenting the JVM with Guard check points.

Test cases will be developed with Agent implementations.

Eventually any changes made to classes in package au.net.zeus.hps will be ported back to the JGDMS project, but will be broken out into a separate module and jar file, to avoid any dependencies on JGDMS.

This prototype is intended to be extensible, to allow full customisation of Guard checks.  Similarly to the au.net.zeus.guardsJavaPermissions Provider, downstream projects can implement their own providers, so that their existing Permission implementations are found using Guards, instead of being directly constructed, allowing their replacement by alternative implementations.

This prototype authorization layer framework is intended to only support Java LTS release versions, to minimise the security auditing work required to lock down the JVM.

Unlike Java's AccessController, application code must make a privileged call in order to use privileged mode and that privileged call is only applicable to the running thread.  This decision was made, due to the inability of inheriting Thread context and in light of the difficulties tracking privileges accross executors.  - However this introduces a problem, while it prevents viral permissions, it prevents domains that not specifically nominated to be given Authorization from being granted any privileges at all.

Library code that doesn't support this will need to be either wrapped, with privileged calls, or agents used to make certain calls privileged, for multi threaded applications.

## Why we can't just reimpliment the existing AccessController and AccessControlContext model

In Java's existing Authorization framework, when Thread's are created, they record the AccessControlContext of the thread that called their constructor.  This allows the AccessController to track the call context back to the originating thread, to capture all domains, that may be involved.  One flaw in this approach, is that of Runnable and Callable tasks, they too should have recorded their context during creation, however as they are interfaces and not abstract classes, they cannot.

Unfortunately AccessController::doPrivilged methods are being removed, we would like to capture the intent of these methods, which we can, at least until they're removed.   We need to campaign for OpenJDK to keep them as no-op's.

We are unable to replicate recording of a Thread's inherited context, for this reason, if a privileged call has not been made, there can be no privileges granted, as we are unable to reason about where the current thread originated, or how it was created, even if all domains on the stack are privileged.  However we can reason that since a Thread is Runnable and because the Runnable interface return is void, it is unlikely to leak information.  Of greater concern is the fact that Callable and Runnable tasks may be submitted to an Executor, and that no inherited context has been recorded, only the domain of the Runnable or Callable implementation has been recorded.  As we know from deserialziation gadget attacks, the attacker attempts to gain privilged context by using a vulnerability, basically an unauthenticated connection, to create object with privilged domains, without a domain on the stack representing the attacker.   Subject is a first class citizen in Authorization in HPS, using the principle of least privilege, first ensure that privilged domains are only granted the privilges they require, then developers are encouraged to authenticate connections, so that Permission's can be granted to a Subject's Principal's, not a CodeSource.

It is extremely important that privilges are only used when needed, the developer can indicate their desire to use privileges, by making a privileged call.  If the developer hasn't made a privileged call, then an attacker using a gadget, cannot use their privileges, neither can an admistrator grant AllPermission.  Granting of AllPermission is a broken shortcut, to cover the deficit of tooling provided for policy file management.  The developer can constrain the use of privileges to a small section of code, that's relatively easy to audit.  This is in stark contrast to Java's original privilege model, where the developer has to understand how to create an unprivileged AccessControlContext and make an AccessController::doPrivileged call with it.

Because we don't generally grant privileges outside of privileged calls, it reduces the size of the code that needs auditing.
