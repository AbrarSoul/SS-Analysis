package com.fasterxml.jackson.databind.jsontype.impl;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.fasterxml.jackson.databind.BeanDescription;
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
        Set<String> denylist = new HashSet<String>();
        // Courtesy of [https://github.com/kantega/notsoserial]:
        // (and wrt [databind#1599])
        denylist.add("org.apache.commons.collections.functors.InvokerTransformer");
        denylist.add("org.apache.commons.collections.functors.InstantiateTransformer");
        denylist.add("org.apache.commons.collections4.functors.InvokerTransformer");
        denylist.add("org.apache.commons.collections4.functors.InstantiateTransformer");
        denylist.add("org.codehaus.groovy.runtime.ConvertedClosure");
        denylist.add("org.codehaus.groovy.runtime.MethodClosure");
        denylist.add("org.springframework.beans.factory.ObjectFactory");
        denylist.add("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        denylist.add("org.apache.xalan.xsltc.trax.TemplatesImpl");
        // [databind#1680]: may or may not be problem, take no chance
        denylist.add("com.sun.rowset.JdbcRowSetImpl");
        // [databind#1737]; JDK provided
        denylist.add("java.util.logging.FileHandler");
        denylist.add("java.rmi.server.UnicastRemoteObject");
        // [databind#1737]; 3rd party
//s.add("org.springframework.aop.support.AbstractBeanFactoryPointcutAdvisor"); // deprecated by [databind#1855]
        denylist.add("org.springframework.beans.factory.config.PropertyPathFactoryBean");
        // [databind#2680]
        denylist.add("org.springframework.aop.config.MethodLocatingFactoryBean");
        denylist.add("org.springframework.beans.factory.config.BeanReferenceFactoryBean");

// s.add("com.mchange.v2.c3p0.JndiRefForwardingDataSource"); // deprecated by [databind#1931]
// s.add("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource"); // - "" -
        // [databind#1855]: more 3rd party
        denylist.add("org.apache.tomcat.dbcp.dbcp2.BasicDataSource");
        denylist.add("com.sun.org.apache.bcel.internal.util.ClassLoader");
        // [databind#1899]: more 3rd party
        denylist.add("org.hibernate.jmx.StatisticsService");
        denylist.add("org.apache.ibatis.datasource.jndi.JndiDataSourceFactory");
        // [databind#2032]: more 3rd party; data exfiltration via xml parsed ext entities
        denylist.add("org.apache.ibatis.parsing.XPathParser");

        // [databind#2052]: Jodd-db, with jndi/ldap lookup
        denylist.add("jodd.db.connection.DataSourceConnectionProvider");

        // [databind#2058]: Oracle JDBC driver, with jndi/ldap lookup
        denylist.add("oracle.jdbc.connector.OracleManagedConnectionFactory");
        denylist.add("oracle.jdbc.rowset.OracleJDBCRowSet");

        // [databind#2097]: some 3rd party, one JDK-bundled
        denylist.add("org.slf4j.ext.EventData");
        denylist.add("flex.messaging.util.concurrent.AsynchBeansWorkManagerExecutor");
        denylist.add("com.sun.deploy.security.ruleset.DRSHelper");
        denylist.add("org.apache.axis2.jaxws.spi.handler.HandlerResolverImpl");

        // [databind#2186], [databind#2670]: yet more 3rd party gadgets
        denylist.add("org.jboss.util.propertyeditor.DocumentEditor");
        denylist.add("org.apache.openjpa.ee.RegistryManagedRuntime");
        denylist.add("org.apache.openjpa.ee.JNDIManagedRuntime");
        denylist.add("org.apache.openjpa.ee.WASRegistryManagedRuntime"); // [#2670] addition
        denylist.add("org.apache.axis2.transport.jms.JMSOutTransportInfo");

        // [databind#2326] (2.9.9)
        denylist.add("com.mysql.cj.jdbc.admin.MiniAdmin");

        // [databind#2334]: logback-core (2.9.9.1)
        denylist.add("ch.qos.logback.core.db.DriverManagerConnectionSource");

        // [databind#2341]: jdom/jdom2 (2.9.9.1)
        denylist.add("org.jdom.transform.XSLTransformer");
        denylist.add("org.jdom2.transform.XSLTransformer");

        // [databind#2387], [databind#2460]: EHCache
        denylist.add("net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup");
        denylist.add("net.sf.ehcache.hibernate.EhcacheJtaTransactionManagerLookup");

        // [databind#2389]: logback/jndi
        denylist.add("ch.qos.logback.core.db.JNDIConnectionSource");

        // [databind#2410]: HikariCP/metricRegistry config
        denylist.add("com.zaxxer.hikari.HikariConfig");
        // [databind#2449]: and sub-class thereof
        denylist.add("com.zaxxer.hikari.HikariDataSource");

        // [databind#2420]: CXF/JAX-RS provider/XSLT
        denylist.add("org.apache.cxf.jaxrs.provider.XSLTJaxbProvider");

        // [databind#2462]: commons-configuration / -2
        denylist.add("org.apache.commons.configuration.JNDIConfiguration");
        denylist.add("org.apache.commons.configuration2.JNDIConfiguration");

        // [databind#2469]: xalan
        denylist.add("org.apache.xalan.lib.sql.JNDIConnectionPool");
        // [databind#2704]: xalan2
        denylist.add("com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool");

        // [databind#2478]: comons-dbcp, p6spy
        denylist.add("org.apache.commons.dbcp.datasources.PerUserPoolDataSource");
        denylist.add("org.apache.commons.dbcp.datasources.SharedPoolDataSource");
        denylist.add("com.p6spy.engine.spy.P6DataSource");

        // [databind#2498]: log4j-extras (1.2)
        denylist.add("org.apache.log4j.receivers.db.DriverManagerConnectionSource");
        denylist.add("org.apache.log4j.receivers.db.JNDIConnectionSource");

        // [databind#2526]: some more ehcache
        denylist.add("net.sf.ehcache.transaction.manager.selector.GenericJndiSelector");
        denylist.add("net.sf.ehcache.transaction.manager.selector.GlassfishSelector");

        // [databind#2620]: xbean-reflect
        denylist.add("org.apache.xbean.propertyeditor.JndiConverter");

        // [databind#2631]: shaded hikari-config
        denylist.add("org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig");

        // [databind#2634]: ibatis-sqlmap, anteros-core
        denylist.add("com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig");
        denylist.add("br.com.anteros.dbcp.AnterosDBCPConfig");

        // [databind#2642]: javax.swing (jdk)
        denylist.add("javax.swing.JEditorPane");

        // [databind#2648], [databind#2653]: shire-core
        denylist.add("org.apache.shiro.realm.jndi.JndiRealmFactory");
        denylist.add("org.apache.shiro.jndi.JndiObjectFactory");

        // [databind#2658]: ignite-jta (, quartz-core)
        denylist.add("org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup");
        denylist.add("org.apache.ignite.cache.jta.jndi.CacheJndiTmFactory");
        denylist.add("org.quartz.utils.JNDIConnectionProvider");

        // [databind#2659]: aries.transaction.jms
        denylist.add("org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory");
        denylist.add("org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory");

        // [databind#2660]: caucho-quercus
        denylist.add("com.caucho.config.types.ResourceRef");

        // [databind#2662]: aoju/bus-proxy
        denylist.add("org.aoju.bus.proxy.provider.RmiProvider");
        denylist.add("org.aoju.bus.proxy.provider.remoting.RmiProvider");

        // [databind#2664]: activemq-core, activemq-pool, activemq-pool-jms

        denylist.add("org.apache.activemq.ActiveMQConnectionFactory"); // core
        denylist.add("org.apache.activemq.ActiveMQXAConnectionFactory");
        denylist.add("org.apache.activemq.spring.ActiveMQConnectionFactory");
        denylist.add("org.apache.activemq.spring.ActiveMQXAConnectionFactory");
        denylist.add("org.apache.activemq.pool.JcaPooledConnectionFactory"); // pool
        denylist.add("org.apache.activemq.pool.PooledConnectionFactory");
        denylist.add("org.apache.activemq.pool.XaPooledConnectionFactory");
        denylist.add("org.apache.activemq.jms.pool.XaPooledConnectionFactory"); // pool-jms
        denylist.add("org.apache.activemq.jms.pool.JcaPooledConnectionFactory");
        
        // [databind#2666]: apache/commons-jms
        denylist.add("org.apache.commons.proxy.provider.remoting.RmiProvider");

        // [databind#2682]: commons-jelly
        denylist.add("org.apache.commons.jelly.impl.Embedded");

        // [databind#2688]: apache/drill
        denylist.add("oadd.org.apache.xalan.lib.sql.JNDIConnectionPool");

        // [databind#2698]: weblogic w/ oracle/aq-jms
        // (note: dependency not available via Maven Central, but as part of
        // weblogic installation, possibly fairly old version(s))
        denylist.add("oracle.jms.AQjmsQueueConnectionFactory");
        denylist.add("oracle.jms.AQjmsXATopicConnectionFactory");
        denylist.add("oracle.jms.AQjmsTopicConnectionFactory");
        denylist.add("oracle.jms.AQjmsXAQueueConnectionFactory");
        denylist.add("oracle.jms.AQjmsXAConnectionFactory");

        // [databind#2764]: org.jsecurity:
        denylist.add("org.jsecurity.realm.jndi.JndiRealmFactory");

        // [databind#2798]: com.pastdev.httpcomponents:
        denylist.add("com.pastdev.httpcomponents.configuration.JndiConfiguration");
        
        DEFAULT_NO_DESER_CLASS_NAMES = Collections.unmodifiableSet(denylist);
    }

    /**
     * Set of class names of types that are never to be deserialized.
     */
    protected Set<String> _cfgIllegalClassNames = DEFAULT_NO_DESER_CLASS_NAMES;

    private final static SubTypeValidator instance = new SubTypeValidator();

    protected SubTypeValidator() { }

    public static SubTypeValidator instance() { return instance; }

    public void validateSubType(DeserializationContext ctxt, JavaType type,
            BeanDescription beanDesc) throws JsonMappingException
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

        ctxt.reportBadTypeDefinition(beanDesc,
                "Illegal type (%s) to deserialize: prevented for security reasons", full);
    }
}
