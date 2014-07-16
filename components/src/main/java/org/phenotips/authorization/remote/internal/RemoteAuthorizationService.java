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
package org.phenotips.authorization.remote.internal;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import net.sf.json.JSONObject;

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
import org.phenotips.authorization.remote.AuthorizationService;
import org.phenotips.data.Patient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.cache.CacheFactory;
import org.xwiki.cache.infinispan.internal.InfinispanCacheFactory;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.security.authorization.internal.XWikiCachingRightService;
import org.xwiki.users.User;
import org.xwiki.users.UserManager;

/**
 * @version $Id$
 */
@Component
@Named("remote-json")
@Singleton
public class RemoteAuthorizationService implements AuthorizationService, Initializable
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
    private UserManager userManager;

    private Cache<String, Boolean> cache;

    @Override
    public int getPriority()
    {
        return 300;
    }

    @Override
    public Boolean hasAccess(String access, Patient patient)
    {
        return hasAccess(access, userManager.getCurrentUser(), patient);
    }

    @Override
    public Boolean hasAccess(String access, String username, Patient patient)
    {
        return hasAccess(access, userManager.getUser(username, true), patient);
    }

    @Override
    public Boolean hasAccess(String access, User user, Patient patient)
    {
        String requestedRight = XWikiCachingRightService.actionToRight(access).getName();
        String username = user.getUsername();
        String internalId = patient.getId();
        String externalId = patient.getExternalId();
        String cacheKey = MessageFormat.format("{}::{}::{}", requestedRight, username, internalId);
        Boolean cachedAuthorization = cache.get(cacheKey);
        if (cachedAuthorization != null) {
            return cachedAuthorization.booleanValue();
        }
        byte decision = remoteCheck(requestedRight, username, internalId, externalId);
        if (decision == GRANTED) {
            return true;
        }
        return null;
    }

    @Override
    public void initialize() throws InitializationException
    {
        cache = ((InfinispanCacheFactory) factory).getCacheManager().getCache("RemoteAuthorizationService", true);
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
                    cache.remove(cacheKey);
                    return;
                } else if (StringUtils.equals("max-age", cacheSetting.getName())) {
                    validity = Long.parseLong(cacheSetting.getValue());
                }
            }
        }

        if (validity > 0) {
            cache.put(cacheKey, value, validity, TimeUnit.SECONDS);
        } else if (validity != Long.MIN_VALUE) {
            cache.remove(cacheKey);
        }
    }
}
