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

Unlike Java's AccessController, application code must make a privileged call in order to use privileged mode and that privileged call is only applicable to the running thread.  This decision was made, due to the inability of inheriting Thread context and in light of the difficulties tracking privileges accross executors.  - However this introduces a problem, while it prevents viral permissions, it prevents not specifically submitted to be allowed to be granted privileges from being granted any privileges at all.

Library code that doesn't support this will need to be either wrapped, with privileged calls, or agents used to make certain calls privileged, for multi threaded applications.
