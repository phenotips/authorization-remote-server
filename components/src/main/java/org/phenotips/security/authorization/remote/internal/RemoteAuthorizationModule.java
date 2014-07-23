/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.phenotips.security.authorization.remote.internal;

import org.phenotips.data.Patient;
import org.phenotips.data.PatientRepository;
import org.phenotips.security.authorization.AuthorizationModule;

import org.xwiki.cache.Cache;
import org.xwiki.cache.CacheException;
import org.xwiki.cache.CacheFactory;
import org.xwiki.cache.config.LRUCacheConfiguration;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.users.User;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.MessageFormat;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;

import net.sf.json.JSONObject;

/**
 * Rights checking class that respects the access level granted by a remote server. PhenoTips sends a JSON payload,
 * containing the following information: <code>
 *   {
 *     "username": "someUserName",
 *     "access" : "view",
 *     "patient-id" : "P0123456",
 *     "patient-eid" : "PATIENT_1234"
 *   }
 * </code>
 * <p>
 * The server must reply with a {@code 200 OK} response if the requested access is granted, or {@code 403 Forbidden} if
 * access is denied. Any other response is considered invalid, and the authorization check falls back to the default
 * PhenoTips rights checking.
 * </p>
 * <p>
 * By default, if no cache headers are received, the right is going to be cached for 1 minute. To disable caching, send
 * a {@code no-cache} or {@code no-store} {@code Cache-Control} header.
 * </p>
 * <p>
 * This module has priority 500.
 * </p>
 *
 * @version $Id$
 * @since 1.0M1
 */
@Component
@Named("remote-json")
@Singleton
public class RemoteAuthorizationModule implements AuthorizationModule, Initializable
{
    /** The xwiki.properties key used to configure the remote server URL where authorization requests will be sent. */
    public static final String CONFIGURATION_KEY = "phenotips.security.authorization.remote.url";

    private static final byte GRANTED = 1;

    private static final byte DENIED = 2;

    private static final byte UNKNWON = 0;

    private static final byte ERROR = -1;

    /** Performs HTTP requests to the remote authorization server. */
    private final CloseableHttpClient client = HttpClients.createSystem();

    /** Logging helper object. */
    @Inject
    private Logger logger;

    @Inject
    @Named("infinispan")
    private CacheFactory factory;

    private Cache<Boolean> cache;

    @Inject
    @Named("restricted")
    private ConfigurationSource configuration;

    @Inject
    private PatientRepository patientRepository;

    private URI remoteServiceURL;

    @Override
    public int getPriority()
    {
        return 500;
    }

    @Override
    public Boolean hasAccess(User user, Right access, DocumentReference document)
    {
        if (user == null || access == null || document == null) {
            return null;
        }
        Patient patient = this.patientRepository.getPatientById(document.toString());
        if (patient == null) {
            return null;
        }
        String requestedRight = access.getName();
        String username = user.getUsername();
        String internalId = patient.getId();
        String externalId = patient.getExternalId();
        String cacheKey = getCacheKey(username, requestedRight, internalId);
        Boolean cachedAuthorization = this.cache.get(cacheKey);
        if (cachedAuthorization != null) {
            return cachedAuthorization;
        }
        Boolean result = null;
        byte decision = remoteCheck(requestedRight, username, internalId, externalId);
        if (decision == GRANTED) {
            result = Boolean.TRUE;
        } else if (decision == DENIED) {
            result = Boolean.FALSE;
        }
        return result;
    }

    @Override
    public void initialize() throws InitializationException
    {
        String configuredURL = this.configuration.getProperty(CONFIGURATION_KEY);
        if (StringUtils.isBlank(configuredURL)) {
            throw new InitializationException(this.getClass().getSimpleName()
                + " requires a valid URL to be configured in xwiki.properties under the " + CONFIGURATION_KEY + " key");
        }
        try {
            this.remoteServiceURL = new URI(configuredURL);
        } catch (URISyntaxException ex) {
            throw new InitializationException("Invalid URL configured for " + this.getClass().getSimpleName() + ": "
                + configuredURL, ex);
        }
        LRUCacheConfiguration config = new LRUCacheConfiguration("RemoteAuthorizationService", 1000, 60);
        try {
            this.cache = this.factory.newCache(config);
        } catch (CacheException ex) {
            throw new InitializationException("Failed to create authorization cache: " + ex.getMessage(), ex);
        }
    }

    private byte remoteCheck(String right, String username, String internalId, String externalId)
    {
        HttpPost method = new HttpPost(this.remoteServiceURL);

        JSONObject payload = new JSONObject();
        payload.element("access", right);
        payload.element("username", username);
        payload.element("patient-id", internalId);
        payload.element("patient-eid", externalId);
        method.setEntity(new StringEntity(payload.toString(), ContentType.APPLICATION_JSON));
        CloseableHttpResponse response = null;
        try {
            response = this.client.execute(method);
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                cacheResponse(getCacheKey(username, right, internalId), Boolean.TRUE, response);
                return GRANTED;
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_FORBIDDEN) {
                cacheResponse(getCacheKey(username, right, internalId), Boolean.FALSE, response);
                return DENIED;
            }
        } catch (IOException ex) {
            this.logger.warn("Failed to communicate with the authorization server: {}", ex.getMessage(), ex);
            return ERROR;
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    // Just ignore, this shouldn't happen
                }
            }
        }
        return UNKNWON;
    }

    private void cacheResponse(String cacheKey, Boolean value, HttpResponse response)
    {
        Header cacheHeader = response.getLastHeader("Cache-Control");
        if (cacheHeader != null) {
            for (HeaderElement cacheSetting : cacheHeader.getElements()) {
                if (StringUtils.equals("no-cache", cacheSetting.getName())
                    || StringUtils.equals("no-store", cacheSetting.getName())) {
                    this.cache.remove(cacheKey);
                    return;
                }
            }
        }

        this.cache.set(cacheKey, value);
    }

    private String getCacheKey(String username, String right, String patientId)
    {
        return MessageFormat.format("{0}::{1}::{2}", username, right, patientId);
    }
}
