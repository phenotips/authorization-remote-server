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
package org.phenotips.authorization.remote;

import org.phenotips.data.Patient;
import org.phenotips.data.PatientRepository;

import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.internal.XWikiCachingRightService;

import java.io.IOException;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiRightService;
import com.xpn.xwiki.web.Utils;

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
public class RemoteValidationRightServiceImpl extends XWikiCachingRightService implements XWikiRightService
{
    /** Logging helper object. */
    private static final Logger LOGGER = LoggerFactory.getLogger(RemoteValidationRightServiceImpl.class);

    private static final byte GRANTED = 1;

    private static final byte DENIED = 2;

    private static final byte UNKNWON = 0;

    private static final byte ERROR = -1;

    @SuppressWarnings("deprecation")
    private DocumentReferenceResolver<String> usernameReferenceResolver = Utils.getComponent(
        DocumentReferenceResolver.TYPE_STRING, "currentmixed");

    /** Performs HTTP requests to the remote authorization server. */
    private CloseableHttpClient client = HttpClients.createSystem();

    @Override
    public boolean checkAccess(String action, XWikiDocument doc, XWikiContext context) throws XWikiException
    {
        if (doc.getXObject(Patient.CLASS_REFERENCE) != null) {
            Right requestedRight = actionToRight(action);
            @SuppressWarnings("deprecation")
            PatientRepository repo = Utils.getComponent(PatientRepository.class);
            Patient patient = repo.getPatientById(doc.getDocumentReference().toString());
            byte decision =
                remoteCheck(requestedRight.getName(), context.getUserReference().getName(), patient.getId(),
                    patient.getExternalId());
            if (decision == GRANTED) {
                return true;
            } else if (decision == DENIED) {
                return false;
            }
        }

        return super.checkAccess(action, doc, context);
    }

    @Override
    public boolean hasAccessLevel(String right, String username, String docname, XWikiContext context)
        throws XWikiException
    {
        @SuppressWarnings("deprecation")
        PatientRepository repo = Utils.getComponent(PatientRepository.class);
        Patient patient = repo.getPatientById(docname);
        if (patient != null) {
            Right requestedRight = actionToRight(right);
            byte decision =
                remoteCheck(requestedRight.getName(), this.usernameReferenceResolver.resolve(username).getName(),
                    patient.getId(), patient.getExternalId());
            if (decision == GRANTED) {
                return true;
            } else if (decision == DENIED) {
                return false;
            }
        }

        return super.hasAccessLevel(right, username, docname, context);
    }

    private byte remoteCheck(String right, String username, String internalId, String externalId)
    {
        // FIXME Add a cache
        // FIXME Get the URL from a configuration
        HttpPost method = new HttpPost("http://localhost:8080/bin/CheckAuth");

        JSONObject payload = new JSONObject();
        payload.element("access", right);
        payload.element("username", username);
        payload.element("patient-id", internalId);
        payload.element("patient-eid", externalId);
        method.setEntity(new StringEntity(payload.toString(), ContentType.APPLICATION_JSON));

        try {
            CloseableHttpResponse response = this.client.execute(method);
            // FIXME Cache the response, take into account the cache settings sent by the server
            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                return GRANTED;
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_FORBIDDEN) {
                return DENIED;
            }
        } catch (ClientProtocolException ex) {
            LOGGER.warn("Bad authorization server, invalid HTTP communication: {}", ex.getMessage());
            return ERROR;
        } catch (IOException ex) {
            LOGGER.warn("Failed to communicate with the authorization server: {}", ex.getMessage(), ex);
            return ERROR;
        }
        return UNKNWON;
    }
}
