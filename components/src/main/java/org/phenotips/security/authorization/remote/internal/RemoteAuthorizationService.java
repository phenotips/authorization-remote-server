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

import org.xwiki.cache.CacheFactory;
import org.xwiki.cache.infinispan.internal.InfinispanCacheFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.users.User;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.DateUtils;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.infinispan.Cache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * PhenoTips rights checking, which uses locally defined ACLs.
 * </p>
 * <p>
 * If the response contains a {@code Cache-Control} or {@code Expires} header, then this authorization decision is going
 * to be cached according to those headers. If a {@code Cache-Control: max-age} or {@code Expires} value is sent, the
 * response is going to be cached for that amount of time. By default, if no cache headers are received, the right is
 * going to be cached for 1 minute. To disable caching, send a {@code no-cache}, {@code no-store}, or 0 {@code max-age}
 * {@code Cache-Control} header, or an {@code Expires} date in the past.
 * </p>
 *
 * @version $Id$
 * @since 1.0M1
 */
@Component
@Named("remote-json")
@Singleton
public class RemoteAuthorizationService implements AuthorizationModule, Initializable
{
    /** Logging helper object. */
    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteAuthorizationService.class);

    private static final byte GRANTED = 1;

    private static final byte DENIED = 2;

    private static final byte UNKNWON = 0;

    private static final byte ERROR = -1;

    /** Performs HTTP requests to the remote authorization server. */
    private final CloseableHttpClient client = HttpClients.createSystem();

    @Inject
    @Named("infinispan")
    private CacheFactory factory;

    @Inject
    private PatientRepository patientRepository;

    private Cache<String, Boolean> cache;

    @Override
    public int getPriority()
    {
        return 300;
    }

    @Override
    public Boolean hasAccess(User user, Right access, DocumentReference document)
    {
        Patient patient = this.patientRepository.getPatientById(document.toString());
        if (user == null || patient == null) {
            return null;
        }
        String requestedRight = access.getName();
        String username = user.getUsername();
        String internalId = patient.getId();
        String externalId = patient.getExternalId();
        String cacheKey = MessageFormat.format("{0}::{1}::{2}", requestedRight, username, internalId);
        Boolean cachedAuthorization = this.cache.get(cacheKey);
        if (cachedAuthorization != null) {
            return cachedAuthorization;
        }
        byte decision = remoteCheck(requestedRight, username, internalId, externalId);
        if (decision == GRANTED) {
            return Boolean.TRUE;
        } else if (decision == DENIED) {
            return Boolean.FALSE;
        }
        return null;
    }

    @Override
    public void initialize() throws InitializationException
    {
        this.cache =
            ((InfinispanCacheFactory) this.factory).getCacheManager().getCache("RemoteAuthorizationService", true);
    }

    private byte remoteCheck(String right, String username, String internalId, String externalId)
    {
        // FIXME Get the URL from a configuration
        HttpPost method = new HttpPost("http://localhost:8080/bin/CheckAuth");

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
                // FIXME cacheKey missing
                cacheResponse("", Boolean.TRUE, response);
                return GRANTED;
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_FORBIDDEN) {
                // FIXME cacheKey missing
                cacheResponse("", Boolean.FALSE, response);
                return DENIED;
            }
        } catch (ClientProtocolException ex) {
            LOGGER.warn("Bad authorization server, invalid HTTP communication: {}", ex.getMessage());
            return ERROR;
        } catch (IOException ex) {
            LOGGER.warn("Failed to communicate with the authorization server: {}", ex.getMessage(), ex);
            return ERROR;
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException ex) {
                    // Doesn't matter
                    LOGGER.debug("Exception while closing HTTP response: {}", ex.getMessage());
                }
            }
        }
        return UNKNWON;
    }

    private void cacheResponse(String cacheKey, Boolean value, HttpResponse response)
    {
        long validity = Long.MIN_VALUE;

        // First take into account the Expires header
        Header expiresHeader = response.getLastHeader("Expires");
        if (expiresHeader != null) {
            Date expires = DateUtils.parseDate(expiresHeader.getValue());
            validity = (expires.getTime() - System.currentTimeMillis()) / 1000;
        }

        // RFC 2616 states that the Cache-Control header takes precedence over Expires
        Header cacheHeader = response.getLastHeader("Cache-Control");
        if (cacheHeader != null) {
            for (HeaderElement cacheSetting : cacheHeader.getElements()) {
                if (StringUtils.equals("no-cache", cacheSetting.getName())
                    || StringUtils.equals("no-store", cacheSetting.getName())) {
                    this.cache.remove(cacheKey);
                    return;
                } else if (StringUtils.equals("max-age", cacheSetting.getName())) {
                    validity = Long.parseLong(cacheSetting.getValue());
                }
            }
        }

        if (validity > 0) {
            this.cache.put(cacheKey, value, validity, TimeUnit.SECONDS);
        } else if (validity != Long.MIN_VALUE) {
            this.cache.remove(cacheKey);
        } else {
            this.cache.put(cacheKey, value, 60, TimeUnit.SECONDS);
        }
    }
}
