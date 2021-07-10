# HighPerformanceSecurity

Note the code in package au.net.zeus.hps is taken from JGDMS to demonstrate the security technologies utilised by that project, so they are more readable and understandable.  This is not intended for production as test code hasn't been copied across.  If you want to use these libraries they can be found on Maven Central by adding the following dependency:

        <dependency>
            <groupId>au.net.zeus.jgdms</groupId>
            <artifactId>jgdms-platform</artifactId>
            <version>${project.version}</version>
        </dependency>

Code is package au.net.zeus.auth is intended to communicate concepts around a new authorization layer, post Java 17.  The package au.net.zeus.guards provides Guards implementations for existing JDK Permission classes.  An agents package will be provided in the near future, for instrumenting the JVM with Guard check points.

Test cases will be developed with Agent implementations.

Eventually any changes made to classes in package au.net.zeus.hps will be ported back to the JGDMS project, but will be broken out into a separate module and jar file, to avoid any dependencies on JGDMS.

This prototype is intended to be extensible, to allow full customisation of Guard checks.  Similarly to the au.net.zeus.guardsJavaPermissions Provider, downstream projects can implement their own providers, so that their existing Permission implementations are found using Guards, instead of being directly constructed, allowing their replacement by alternative implementations.

This prototype authorization layer framework is intended to only support Java LTS release versions, to minimise the security auditing work required to lock down the JVM.

Unlike Java's AccessController, application code must make a privileged call in order to use privileged mode and that privileged call is only applicable to the running thread.  This decision was made, due to the inability of inheriting Thread context and in light of the difficulties tracking privileges accross executors.

Library code that doesn't support this will need to be either wrapped, with privileged calls, or agents used to make certain calls privileged, for multi threaded applications.
