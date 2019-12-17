package de.trustable.ca3s.cert.bundle;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TimedRenewalCertMap {

	private static final Logger LOG = LoggerFactory.getLogger(TimedRenewalCertMap.class);

	private HashMap<String, KeyCertBundle> bundleSet = new HashMap<String, KeyCertBundle>();

	private BundleFactory bundleFactory;

	TimedRenewalCertMap(final BundleFactory bundleFactory) {
		LOG.debug("cTor TimedRenewalCertMap(bundleFac)");

		this.bundleFactory = bundleFactory;

		TimerTask repeatedTask = new TimerTask() {
			public void run() {

				Date refreshDate = new Date(System.currentTimeMillis() + (24L * 3600L * 1000L));
				Date now = new Date();
				LOG.info("Task 'renewal' started on " + now + ", refreshing all certificates expiring before "
						+ refreshDate);

				for (KeyCertBundle kcb : bundleSet.values()) {
					String bundleName = kcb.getAlias();
					Date notAfter = kcb.getCertificate().getNotAfter();
					LOG.debug("checking renewal for alias '{}', expiring on {} ", bundleName, notAfter);
					if(now.after(notAfter)) {
						LOG.error("renewal in time FAILED for alias '{}', expired on {} !", bundleName, notAfter);
					}
					
					if (refreshDate.after(notAfter)) {
						LOG.info("renewal required for alias '{}', expiring on {} ", bundleName, notAfter);
						try {
							bundleSet.put(bundleName, bundleFactory.newKeyBundle(bundleName));

						} catch (GeneralSecurityException e) {
							LOG.warn("renewal for alias '{}' expiring on {} failed : {}", bundleName,notAfter, e.getMessage());
							LOG.debug("certificate renewal failed", e);
						}
					}
				}

			}
		};

		Timer timer = new Timer("Timer");

		long delay = 30L * 60L * 1000L;
		long period = 30L * 60L * 1000L;
		timer.scheduleAtFixedRate(repeatedTask, delay, period);

	}

	public KeyCertBundle findBundleForAlias(final String bundleName) {

		if (!bundleSet.containsKey(bundleName)) {
			LOG.warn("findBundleForAlias('{}') failed to find KeyCertBundle", bundleName);
			try {
				bundleSet.put(bundleName, bundleFactory.newKeyBundle(bundleName));
			} catch (GeneralSecurityException e) {
				LOG.warn("creation / renewal for alias '{}' failed : {}", bundleName, e.getMessage());
				LOG.debug("certificate creation / renewal failed", e);
			}
		}

		KeyCertBundle kcb = bundleSet.get(bundleName);
		if (kcb != null) {
			X509Certificate x509Cert = (X509Certificate) kcb.getCertificate();
			LOG.info("findBundleForAlias('{}') returns {}", bundleName, x509Cert.getSubjectX500Principal().getName());
		}

		return kcb;

	}

	public static void pause(int ms) {
		try {
			Thread.sleep(ms);
		} catch (InterruptedException e) {
			System.err.format("IOException: %s%n", e);
		}
	}

	public Set<String> aliases() {
		return bundleSet.keySet();
	}

	public boolean containsAlias(String alias) {
		return bundleSet.containsKey(alias);
	}

	public int size() {
		return bundleSet.size();
	}

	public String getAliasForCertificate(final Certificate cert) {

		for (KeyCertBundle kcb : bundleSet.values()) {
			if (kcb.getCertificate().equals(cert)) {
				return kcb.getAlias();
			}
		}
		return null;
	}

	public void put(String alias, Certificate[] chain, Certificate certificate, Key key) {

		KeyCertBundle kbr = new KeyCertBundle(alias, (X509Certificate[]) chain, (X509Certificate) chain[0], key);
		bundleSet.put(alias, kbr);
	}

}
