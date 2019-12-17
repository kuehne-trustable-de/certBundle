package de.trustable.ca3s.cert.bundle;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*******************
 * The SPI for the jshell initializes a simple key Manager. The default 
 * key manager in the JSSE is obtained and set up with the custom key manager.
 * The following system properties are queried to set up the custom key manager
 * <ol>
 * <li><code>jshell.default.keymanager.alg</code>: The default key manager algorithm in the JSSE provider 
 *   (For SunJVM it is SunX509, for IBM JVM it is IbmX509).
 * <li><code>jshell.server_key_map.file</code>: Path to the config file containing the server to key mapping
 * </ol>
 *
 * The custom key manager is initialized with
 * <ol>
 *     <li>An intance of the default key manager provided by the platform.
 *     <li>A mapping of the server names to the key alias.
 * </ol>
 * 
 * @author Abhilash Koneri
 * @since nothing 0.0
 */
public class TimedRenewalKeyManagerFactorySpi  extends KeyManagerFactorySpi
{
    private static final String DEFAULT_ALGO = KeyManagerFactory.getDefaultAlgorithm();

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreImpl.class);

    private TimedRenewalKeyManager keyManager = null;
    private String algoName = null;
    private BundleFactory bundleFactory = null;

    public TimedRenewalKeyManagerFactorySpi(final String algoName, final BundleFactory bundleFactory) {
    	this.algoName = algoName;
    	this.bundleFactory = bundleFactory;
    }
    
    public KeyManager[] engineGetKeyManagers()
    {
    	LOG.debug("TimedRenewalKeyManagerFactorySpi::engineGetKeyManagers()");
        return new KeyManager[]{ keyManager};
    }

    public void engineInit(KeyStore ks, char[] password) 
        throws KeyStoreException, NoSuchAlgorithmException,  UnrecoverableKeyException {
    	
    	LOG.debug("TimedRenewalKeyManagerFactorySpi::engineInit(ks)");

        KeyManagerFactory factory = KeyManagerFactory.getInstance(DEFAULT_ALGO);
        factory.init(ks, password);

        KeyManager[] keyManagers = factory.getKeyManagers();

        if(keyManagers ==  null ||keyManagers.length == 0) {
            throw new NoSuchAlgorithmException("The default algorithm :"+
                    DEFAULT_ALGO+" produced no key managers");
        }
        
        X509KeyManager x509KeyManager = null;

        for(int i=0;i<keyManagers.length; i++)
        {
            if(keyManagers[i] instanceof X509KeyManager){
                x509KeyManager = (X509KeyManager)keyManagers[i];
                break;
            }
        }

        if(x509KeyManager == null){
            throw new NoSuchAlgorithmException("The default algorithm :"+
                    DEFAULT_ALGO+" did not produce a X509 Key manager");
        }
            
        this.keyManager = new TimedRenewalKeyManager(x509KeyManager, bundleFactory);
        
        Security.setProperty("ssl.KeyManagerFactory.algorithm", algoName);

    }

    public void engineInit(ManagerFactoryParameters spec)
    {
    	LOG.debug("TimedRenewalKeyManagerFactorySpi::engineInit(spec), no implementation");
    }

 
}
