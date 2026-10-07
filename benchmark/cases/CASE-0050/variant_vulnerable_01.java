package com.fasterxml.jackson.databind.jsontype.impl;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;

/**
 * Helper class used to encapsulate rules that determine subtypes that
 * are invalid to use, even with default typing, mostly due to security
 * concerns.
 * Used by <code>BeanDeserializerFacotry</code>
 *
 * @since 2.8.11
 */
public class SubTypeValidator
{
    protected final static String PREFIX_SPRING = "org.springframework.";

    protected final static String PREFIX_C3P0 = "com.mchange.v2.c3p0.";

    /**
     * Set of well-known "nasty classes", deserialization of which is considered dangerous
     * and should (and is) prevented by default.
     */
    protected final static Set<String> DEFAULT_NO_DESER_CLASS_NAMES;
    static {
        Set<String> blockedTypes = new HashSet<String>();
        // Courtesy of [https://github.com/kantega/notsoserial]:
        // (and wrt [databind#1599])
        blockedTypes.add("org.apache.commons.collections.functors.InvokerTransformer");
        blockedTypes.add("org.apache.commons.collections.functors.InstantiateTransformer");
        blockedTypes.add("org.apache.commons.collections4.functors.InvokerTransformer");
        blockedTypes.add("org.apache.commons.collections4.functors.InstantiateTransformer");
        blockedTypes.add("org.codehaus.groovy.runtime.ConvertedClosure");
        blockedTypes.add("org.codehaus.groovy.runtime.MethodClosure");
        blockedTypes.add("org.springframework.beans.factory.ObjectFactory");
        blockedTypes.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        blockedTypes.add("org.apache.xalan.xsltc.trax.TemplatesImpl");
        // [databind#1680]: may or may not be problem, take no chance
        blockedTypes.add("com.sun.rowset.JdbcRowSetImpl");
        // [databind#1737]; JDK provided
        blockedTypes.add("java.util.logging.FileHandler");
        blockedTypes.add("java.rmi.server.UnicastRemoteObject");
        // [databind#1737]; 3rd party
//blockedTypes.add("org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor"); // deprecated by [databind#1855]
        blockedTypes.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");

// blockedTypes.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource"); // deprecated by [databind#1931]
// blockedTypes.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"); // - "" -
        // [databind#1855]: more 3rd party
        blockedTypes.add("org.apache.tomcat.dbcp.dbcp2.BasicDataSource");
        blockedTypes.add("com.sun.org.apache.bcel.internal.util.ClassLoader");
        // [databind#1899]: more 3rd party
        blockedTypes.add("org.hibernate.jmx.StatisticsService");
        blockedTypes.add("org.apache.ibatis.datasource.jndi.JndiDataSourceFactory");
        // [databind#2032]: more 3rd party; data exfiltration via xml parsed ext entities
        blockedTypes.add("org.apache.ibatis.parsing.XPathParser");

        // [databind#2052]: Jodd-db, with jndi/ldap lookup
        blockedTypes.add("jodd.db.connection.DataSourceConnectionProvider");

        // [databind#2058]: Oracle JDBC driver, with jndi/ldap lookup
        blockedTypes.add("oracle.jdbc.connector.OracleManagedConnectionFactory");
        blockedTypes.add("oracle.jdbc.rowset.OracleJDBCRowSet");
        // [databind#1899]: more 3rd party
        blockedTypes.add("org.hibernate.jmx.StatisticsService");
        blockedTypes.add("org.apache.ibatis.datasource.jndi.JndiDataSourceFactory");

        // [databind#2097]: some 3rd party, one JDK-bundled
        blockedTypes.add("org.slf4j.ext.EventData");
        blockedTypes.add("flex.messaging.util.concurrent.AsynchBeansWorkManagerExecutor");
        blockedTypes.add("com.sun.deploy.security.ruleset.DRSHelper");
        blockedTypes.add("org.apache.axis2.jaxws.spi.handler.HandlerResolverImpl");

        // [databind#2186]: yet more 3rd party gadgets
        blockedTypes.add("org.jboss.util.propertyeditor.DocumentEditor");
        blockedTypes.add("org.apache.openjpa.ee.RegistryManagedRuntime");
        blockedTypes.add("org.apache.openjpa.ee.JNDIManagedRuntime");
        blockedTypes.add("org.apache.axis2.transport.jms.JMSOutTransportInfo");

        // [databind#2326]
        blockedTypes.add("com.mysql.cj.jdbc.admin.MiniAdmin");        

        // [databind#2334]: logback-core
        blockedTypes.add("ch.qos.logback.core.db.DriverManagerConnectionSource");

        // [databind#2341]: jdom/jdom2
        blockedTypes.add("org.jdom.transform.XSLTransformer");
        blockedTypes.add("org.jdom2.transform.XSLTransformer");

        // [databind#2387], [databind#2460]: EHCache
        blockedTypes.add("net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup");
        blockedTypes.add("net.sf.ehcache.hibernate.EhcacheJtaTransactionManagerLookup");

        // [databind#2389]: logback/jndi
        blockedTypes.add("ch.qos.logback.core.db.JNDIConnectionSource");

        // [databind#2410]: HikariCP/metricRegistry config
        blockedTypes.add("com.zaxxer.hikari.HikariConfig");
        // [databind#2449]: and sub-class thereof
        blockedTypes.add("com.zaxxer.hikari.HikariDataSource");

        // [databind#2420]: CXF/JAX-RS provider/XSLT
        blockedTypes.add("org.apache.cxf.jaxrs.provider.XSLTJaxbProvider");

        // [databind#2462]: commons-configuration / -2
        blockedTypes.add("org.apache.commons.configuration.JNDIConfiguration");
        blockedTypes.add("org.apache.commons.configuration2.JNDIConfiguration");

        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(blockedTypes);
    }

    /**
     * Set of class names of types that are never to be deserialized.
     */
    protected Set<String> _cfgIllegalClassNames = DEFAULT_NO_DESER_CLASS_NAMES;

    private final static SubTypeValidator instance = new SubTypeValidator();

    protected SubTypeValidator() { }

    public static SubTypeValidator instance() { return instance; }

    public void validateSubType(DeserializationContext ctxt, JavaType type)
            throws JsonMappingException
    {
        // There are certain nasty classes that could cause problems, mostly
        // via default typing -- catch them here.
        final Class<?> raw = type.getRawClass();
        String full = raw.getName();

        main_check:
        do {
            if (_cfgIllegalClassNames.contains(full)) {
                break;
            }

            // 18-Dec-2017, tatu: As per [databind#1855], need bit more sophisticated handling
            //    for some Spring framework types
            // 05-Jan-2017, tatu: ... also, only applies to classes, not interfaces
            if (raw.isInterface()) {
                ;
            } else if (full.startsWith(PREFIX_SPRING)) {
                for (Class<?> cls = raw; (cls != null) && (cls != Object.class); cls = cls.getSuperclass()){
                    String name = cls.getSimpleName();
                    // looking for "AbstractBeanFactoryPointcutAdvisor" but no point to allow any is there?
                    if ("AbstractPointcutAdvisor".equals(name)
                            // ditto  for "FileSystemXmlApplicationContext": block all ApplicationContexts
                            || "AbstractApplicationContext".equals(name)) {
                        break main_check;
                    }
                }
            } else if (full.startsWith(PREFIX_C3P0)) {
                // [databind#1737]; more 3rd party
                // s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource");
                // s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
                // [databind#1931]; more 3rd party
                // com.mchange.v2.c3p0.ComboPooledDataSource
                // com.mchange.v2.c3p0.debug.AfterCloseLoggingComboPooledDataSource 
                if (full.endsWith("DataSource")) {
                    break main_check;
                }
            }
            return;
        } while (false);

        throw JsonMappingException.from(ctxt,
                String.format("Illegal type (%s) to deserialize: prevented for security reasons", full));
    }
}
