package de.trustable.ca3s.cert.bundle;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*******************
 * <code>TimedRenewalKeyManager</code> is a key manager
 * 
 * @author
 * 
 */
public class TimedRenewalKeyManager extends X509ExtendedKeyManager {
	
	
    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreImpl.class);

	private X509KeyManager defaultKeyManager;
    private TimedRenewalCertMap certMap;
    
/*    
    public TimedRenewalKeyManager(final X509KeyManager defaultKeyManager, final BundleFactory bundleFactory) {
		LOG.debug("cTor KeyStoreImpl(bundleFac) called");
		
		this.defaultKeyManager = defaultKeyManager;
		this.certMap = new TimedRenewalCertMap(bundleFactory);
   }
*/
    
    public TimedRenewalKeyManager(final X509KeyManager defaultKeyManager, final TimedRenewalCertMap certMap) {
		LOG.debug("cTor KeyStoreImpl(bundleFac) called");
		
		this.defaultKeyManager = defaultKeyManager;
		this.certMap = certMap;
   }

	public X509Certificate[] getCertificateChain(String alias) {
		
		LOG.debug("getCertificateChain({})", alias);

		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		LOG.debug("getCertificateChain({} ) return chain with {} elements", alias, kcb.getCertificateChain().length);
		return kcb.getCertificateChain();
	}

	public PrivateKey getPrivateKey(String alias) {
		LOG.debug("getPrivateKey({}, ***** )", alias);
		
		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.debug("getPrivateKey({}, ***** ) cannot find key for alias ", alias);
			return null;
		}

		LOG.debug("getPrivateKey({}, ***** ) returns key ", alias);
		
		return (PrivateKey) kcb.getKey();

	}


	/*
	 * the following methods are delegated to the default key manager
	 */
	
	/**
	 * 
	 */
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		LOG.debug("chooseClientAlias()");
		return defaultKeyManager.chooseClientAlias(keyType, issuers, socket);
	}

	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		LOG.debug("chooseServerAlias()");
		return defaultKeyManager.chooseServerAlias(keyType, issuers, socket);
	}

	public String[] getClientAliases(String keyType, Principal[] issuers) {
		LOG.debug("getClientAliases()");
		return defaultKeyManager.getClientAliases(keyType, issuers);
	}

	public String[] getServerAliases(String keyType, Principal[] issuers) {
		LOG.debug("getServerAliases()");
		return defaultKeyManager.getServerAliases(keyType, issuers);
	}

	public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
		return chooseClientAlias(keyType, issuers, null);
	}

	public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
		return chooseServerAlias(keyType, issuers, null);
	}

}
