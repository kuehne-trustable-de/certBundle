package de.trustable.ca3s.cert.bundle;

import java.security.GeneralSecurityException;

public interface BundleFactory {

	KeyCertBundle newKeyBundle(String bundleName, long minValiditySeconds) throws GeneralSecurityException;

}