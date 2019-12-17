package de.trustable.ca3s.cert.bundle;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;
import java.util.Vector;

import javax.crypto.SecretKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyStoreImpl extends KeyStoreSpi{

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreImpl.class);

    private TimedRenewalCertMap certMap;
    
     public KeyStoreImpl(final BundleFactory bundleFactory) {
		LOG.debug("cTor KeyStoreImpl(bundleFac) called");
		
		certMap = new TimedRenewalCertMap(bundleFactory);
    }
    

	@Override
	public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
		
		LOG.debug("engineGetKey({}, ***** )", alias);
		
		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.debug("engineGetKey({}, ***** ) throws UnrecoverableKeyException ", alias);
			throw new UnrecoverableKeyException("alias '" + alias + "' unknown");
		}

		LOG.debug("engineGetKey({}, ***** ) returns key ", alias);
		
		return kcb.getKey();
	}

	
	
	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		
		LOG.debug("engineGetCertificateChain({})", alias);

		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		LOG.debug("engineGetCertificateChain({} ) return chain with {} elements", alias, kcb.getCertificateChain().length);
		return kcb.getCertificateChain();
	}

	@Override
	public Certificate engineGetCertificate(String alias) {
		
		LOG.debug("engineGetCertificate({})", alias);

		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		return kcb.getCertificate();
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		LOG.debug("engineGetCreationDate({})", alias);

		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		return kcb.getCreationDate();
	}

	@Override
	public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
			throws KeyStoreException {
		LOG.debug("engineSetKeyEntry({}, chain)", alias, chain.length);
		
		certMap.put( alias, chain, chain[0], key);

//		throw new RuntimeException("engineSetKeyEntry not supported");
	}

	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
		throw new RuntimeException("engineSetKeyEntry not supported");
		
	}

	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
		throw new RuntimeException("engineSetCertificateEntry not supported");
	}

	@Override
	public void engineDeleteEntry(String alias) throws KeyStoreException {
		throw new RuntimeException("engineDeleteEntry not supported");
		
	}

	@Override
	public Enumeration<String> engineAliases() {
		LOG.debug("engineAliases()");
		
		Set<String> aliasSet = certMap.aliases();
		for( String alias: aliasSet) {
			LOG.debug("returning alias {}", alias);
		}
		Vector<String> v = new Vector<String>(aliasSet);
/*		
		if( v.isEmpty()) {
			Properties props = System.getProperties();
			Set keys = props.keySet();
			Consumer action = new Consumer() {

				@Override
				public void accept(Object t) {
					LOG.debug("Prop key {} has value {}",t,  props.getProperty((String) t));
					
				}};
			keys.forEach(action);
			
			v.add("http://localhost:8081/acme/foo/directory");
			LOG.debug("returning alias http://localhost:8081/acme/foo/directory");
		}
*/
		
		return v.elements();
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		LOG.debug("engineContainsAlias({})", alias);

		return certMap.containsAlias(alias);
	}

	@Override
	public int engineSize() {
		LOG.debug("engineSize()");
		return certMap.size();
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		LOG.debug("engineIsKeyEntry({})", alias);
		KeyCertBundle kcb = certMap.findBundleForAlias(alias);
		if( kcb != null ) {
			LOG.info("alias '" + alias + "' found");
			return true;
		}
		return false;
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		LOG.debug("engineIsCertificateEntry({})", alias);
		
		// private key entries only
		return false;
		
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		LOG.debug("engineIsCertificateEntry({})", cert.toString());

		return certMap.getAliasForCertificate(cert);
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		LOG.debug("engineStore(stream, ****) : nothing to do");
	}

	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		
		LOG.info("engineLoad(stream, ****) : retrieving certificate (if neccessary)");
	
	}

    /**
     * Loads this {@code KeyStoreSpi} using the specified {@code
     * LoadStoreParameter}.
     *
     * @param param
     *            the {@code LoadStoreParameter} that specifies how to load this
     *            {@code KeyStoreSpi}, maybe {@code null}.
     * @throws IOException
     *             if a problem occurred while reading from the stream.
     * @throws NoSuchAlgorithmException
     *             if the required algorithm is not available.
     * @throws CertificateException
     *             if the an exception occurred while loading the certificates
     *             of this code {@code KeyStoreSpi}.
     * @throws IllegalArgumentException
     *             if the given {@link KeyStore.LoadStoreParameter} is not
     *             recognized.
     */
    public void engineLoad(KeyStore.LoadStoreParameter param)
            throws IOException, NoSuchAlgorithmException, CertificateException {
    	
    	LOG.info("engineLoad(param) : retrieving certificate (if neccessary)");
	
	}

    /**
     * Indicates whether the entry for the given alias is assignable to the
     * provided {@code Class}.
     *
     * @param alias
     *            the alias for the entry.
     * @param entryClass
     *            the type of the entry.
     * @return {@code true} if the {@code Entry} for the alias is assignable to
     *         the specified {@code entryClass}.
     */
    public boolean engineEntryInstanceOf(String alias,
            Class<? extends KeyStore.Entry> entryClass) {
    	
		LOG.debug("engineEntryInstanceOf({}, entryClass)", alias);
		
        if (!engineContainsAlias(alias)) {
            return false;
        }

        try {
            if (engineIsCertificateEntry(alias)) {
                return entryClass
                        .isAssignableFrom(Class
                                .forName("java.security.KeyStore$TrustedCertificateEntry"));
            }

            if (engineIsKeyEntry(alias)) {
                if (entryClass.isAssignableFrom(Class
                        .forName("java.security.KeyStore$PrivateKeyEntry"))) {
                    return engineGetCertificate(alias) != null;
                }

                if (entryClass.isAssignableFrom(Class
                        .forName("java.security.KeyStore$SecretKeyEntry"))) {
                    return engineGetCertificate(alias) == null;
                }
            }
        } catch (ClassNotFoundException ignore) {}

        return false;
    }

    /**
     * Returns the {@code Entry} with the given alias, using the specified
     * {@code ProtectionParameter}.
     *
     * @param alias
     *            the alias of the requested entry.
     * @param protParam
     *            the {@code ProtectionParameter}, used to protect the requested
     *            entry, maybe {@code null}.
     * @return he {@code Entry} with the given alias, using the specified
     *         {@code ProtectionParameter}.
     * @throws NoSuchAlgorithmException
     *             if the required algorithm is not available.
     * @throws UnrecoverableEntryException
     *             if the entry can not be recovered.
     * @throws KeyStoreException
     *             if this operation fails
     */
    public KeyStore.Entry engineGetEntry(String alias,
            KeyStore.ProtectionParameter protParam) throws KeyStoreException,
            NoSuchAlgorithmException, UnrecoverableEntryException {
    	
		LOG.debug("engineGetEntry({}, protParam)", alias);
		
		
        if (!engineContainsAlias(alias)) {
            return null;
        }
        
        if (engineIsCertificateEntry(alias)) {
            return new KeyStore.TrustedCertificateEntry(
                    engineGetCertificate(alias));
        }
        
        char[] passW = null;
        if (protParam != null) {
            if (protParam instanceof KeyStore.PasswordProtection) {
                try {
                    passW = ((KeyStore.PasswordProtection) protParam)
                            .getPassword();
                } catch (IllegalStateException ee) {
                    throw new KeyStoreException("Password was destroyed", ee);
                }
            } else if (protParam instanceof KeyStore.CallbackHandlerProtection) {
//                passW = getPasswordFromCallBack(protParam);
                throw new UnrecoverableEntryException("ProtectionParameter :PasswordFromCallBack not supported.");
            } else {
                throw new UnrecoverableEntryException("ProtectionParameter object is not "
                                                      + "PasswordProtection: " + protParam);
            }
        }
        
        if (engineIsKeyEntry(alias)) {
            Key key = engineGetKey(alias, passW);
            if (key instanceof PrivateKey) {
                return new KeyStore.PrivateKeyEntry((PrivateKey) key,
                                                    engineGetCertificateChain(alias));
            }
            if (key instanceof SecretKey) {
                return new KeyStore.SecretKeyEntry((SecretKey) key);
            }
        }

        throw new NoSuchAlgorithmException("Unknown KeyStore.Entry object");
    }
    
    /**
     * Stores the given {@code Entry} in this {@code KeyStoreSpi} and associates
     * the entry with the given {@code alias}. The entry is protected by the
     * specified {@code ProtectionParameter}.
     * <p>
     * If the specified alias already exists, it will be reassigned.
     *
     * @param alias
     *            the alias for the entry.
     * @param entry
     *            the entry to store.
     * @param protParam
     *            the {@code ProtectionParameter} to protect the entry.
     * @throws KeyStoreException
     *             if this operation fails.
     */
    public void engineSetEntry(String alias, KeyStore.Entry entry,
            KeyStore.ProtectionParameter protParam) throws KeyStoreException {
    	
		LOG.debug("engineSetEntry({}, entry, protParam)", alias);
		
        if (entry == null) {
            throw new KeyStoreException("entry == null");
        }

        if (engineContainsAlias(alias)) {
            engineDeleteEntry(alias);
        }

        if (entry instanceof KeyStore.TrustedCertificateEntry) {
            KeyStore.TrustedCertificateEntry trE = (KeyStore.TrustedCertificateEntry) entry;
            engineSetCertificateEntry(alias, trE.getTrustedCertificate());
            return;
        }

        char[] passW = null;
        if (protParam instanceof KeyStore.PasswordProtection) {
            try {
                passW = ((KeyStore.PasswordProtection) protParam).getPassword();
            } catch (IllegalStateException ee) {
                throw new KeyStoreException("Password was destroyed", ee);
            }
        } else {
            if (protParam instanceof KeyStore.CallbackHandlerProtection) {
                try {
//                  passW = getPasswordFromCallBack(protParam);
                    throw new UnrecoverableEntryException("ProtectionParameter :PasswordFromCallBack not supported.");
                } catch (Exception e) {
                    throw new KeyStoreException(e);
                }
            } else {
                throw new KeyStoreException("protParam should be PasswordProtection or "
                                            + "CallbackHandlerProtection");
            }
        }

        if (entry instanceof KeyStore.PrivateKeyEntry) {
            KeyStore.PrivateKeyEntry prE = (KeyStore.PrivateKeyEntry) entry;
            engineSetKeyEntry(alias, prE.getPrivateKey(), passW, prE
                    .getCertificateChain());
            return;
        }

        if (entry instanceof KeyStore.SecretKeyEntry) {
            KeyStore.SecretKeyEntry skE = (KeyStore.SecretKeyEntry) entry;
            engineSetKeyEntry(alias, skE.getSecretKey(), passW, null);
            //            engineSetKeyEntry(alias, skE.getSecretKey().getEncoded(), null);
            return;
        }


        throw new KeyStoreException("Entry object is neither PrivateKeyObject nor SecretKeyEntry "
                                    + "nor TrustedCertificateEntry: " + entry);
    }

}
