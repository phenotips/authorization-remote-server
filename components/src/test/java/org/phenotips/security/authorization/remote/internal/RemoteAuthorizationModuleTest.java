/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */
package org.phenotips.security.authorization.remote.internal;

import org.phenotips.data.Patient;
import org.phenotips.data.PatientRepository;
import org.phenotips.security.authorization.AuthorizationModule;

import org.xwiki.cache.Cache;
import org.xwiki.cache.CacheException;
import org.xwiki.cache.CacheFactory;
import org.xwiki.cache.config.CacheConfiguration;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.component.util.ReflectionUtils;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.mockito.MockitoComponentMockingRule;
import org.xwiki.users.User;

import java.io.IOException;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.StatusLine;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for the {@link RemoteAuthorizationModule remote} {@link AuthorizationModule} component.
 *
 * @version $Id$
 */
public class RemoteAuthorizationModuleTest
{
    @Rule
    public final MockitoComponentMockingRule<AuthorizationModule> mocker =
        new MockitoComponentMockingRule<AuthorizationModule>(RemoteAuthorizationModule.class);

    @Mock
    private User user;

    @Mock
    private Right access;

    private DocumentReference document = new DocumentReference("xwiki", "data", "P0000001");

    @Mock
    private Patient patient;

    @Mock
    private CloseableHttpClient client;

    @Mock
    private CloseableHttpResponse response;

    @Mock
    private StatusLine status;

    @Mock
    private Cache<Boolean> cache;

    private String url = "http://host.net/checkAuthorization";

    @Test(expected = InitializationException.class)
    public void noConfigurationThrowsInitializationException() throws Throwable
    {
        try {
            this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document);
        } catch (ComponentLookupException ex) {
            Assert.assertTrue(ex.getCause().getMessage().contains("requires a valid URL to be configured"));
            throw ex.getCause();
        }
    }

    @Test(expected = InitializationException.class)
    public void invalidConfigurationThrowsInitializationException() throws Throwable
    {
        ConfigurationSource configuration = this.mocker.getInstance(ConfigurationSource.class, "restricted");
        when(configuration.getProperty(RemoteAuthorizationModule.CONFIGURATION_KEY)).thenReturn(":NotAnURL");
        try {
            this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document);
        } catch (ComponentLookupException ex) {
            Assert.assertEquals("Invalid URL configured for RemoteAuthorizationModule: :NotAnURL",
                ex.getCause().getMessage());
            throw ex.getCause();
        }
    }

    @Test(expected = InitializationException.class)
    public void cacheMisconfigurationThrowsInitializationException() throws Throwable
    {
        ConfigurationSource configuration = this.mocker.getInstance(ConfigurationSource.class, "restricted");
        when(configuration.getProperty(RemoteAuthorizationModule.CONFIGURATION_KEY)).thenReturn(this.url);
        CacheFactory cf = this.mocker.getInstance(CacheFactory.class, "infinispan");
        when(cf.newCache(any(CacheConfiguration.class))).thenThrow(new CacheException("Bad Cache"));
        try {
            this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document);
        } catch (ComponentLookupException ex) {
            Assert.assertEquals("Failed to create authorization cache: Bad Cache", ex.getCause().getMessage());
            throw ex.getCause();
        }
    }

    @Test
    public void noActionWithNullArguments() throws Exception
    {
        setupNeededComponents();
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(null, this.access, this.document));
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, null, this.document));
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, null));
    }

    @Test
    public void noActionWithNonPatient() throws Exception
    {
        setupNeededComponents();
        PatientRepository repo = this.mocker.getInstance(PatientRepository.class);
        when(repo.getPatientById(this.document.toString())).thenReturn(null);
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
    }

    @Test
    public void hasAccessWithCachedResponse() throws Exception
    {
        setupNeededComponents();
        when(this.cache.get("jdoe::edit::P0000001")).thenReturn(true);
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        when(this.cache.get("jdoe::edit::P0000001")).thenReturn(false);
        Assert.assertFalse(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.client, never()).execute(any(HttpPost.class));
    }

    @Test
    public void grantsAccessWithOKResponse() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenReturn(this.response);
        when(this.response.getStatusLine()).thenReturn(this.status);
        when(this.status.getStatusCode()).thenReturn(HttpStatus.SC_OK);
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.cache).set("jdoe::edit::P0000001", true);
        verify(this.response).close();
    }

    @Test
    public void refusesAccessWithForbiddenResponse() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenReturn(this.response);
        when(this.response.getStatusLine()).thenReturn(this.status);
        when(this.status.getStatusCode()).thenReturn(HttpStatus.SC_FORBIDDEN);
        Assert.assertFalse(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.cache).set("jdoe::edit::P0000001", false);
    }

    @Test
    public void noActionWithOtherResponses() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenReturn(this.response);
        when(this.response.getStatusLine()).thenReturn(this.status);
        for (int i = 0; i < 600; ++i) {
            if (i == HttpStatus.SC_OK || i == HttpStatus.SC_FORBIDDEN) {
                continue;
            }
            when(this.status.getStatusCode()).thenReturn(i);
            Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        }
        // Other responses are not cached
        verify(this.cache, never()).set(Matchers.anyString(), Matchers.anyBoolean());
    }

    @Test
    public void noActionWithHttpExceptions() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenThrow(new ClientProtocolException(), new IOException());
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        Assert.assertNull(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.cache, never()).set(Matchers.anyString(), Matchers.anyBoolean());
    }

    @Test
    public void exceptionWhileClosingRequestIsIgnored() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenReturn(this.response);
        when(this.response.getStatusLine()).thenReturn(this.status);
        when(this.status.getStatusCode()).thenReturn(HttpStatus.SC_OK);
        Mockito.doThrow(new IOException()).when(this.response).close();
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.cache).set("jdoe::edit::P0000001", true);
    }

    @Test
    public void cacheDenyHeadersRespected() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenReturn(this.response);
        when(this.response.getStatusLine()).thenReturn(this.status);
        when(this.status.getStatusCode()).thenReturn(HttpStatus.SC_OK);
        Header header = mock(Header.class);
        when(this.response.getLastHeader("Cache-Control")).thenReturn(header);
        HeaderElement element = mock(HeaderElement.class);
        HeaderElement[] elements = new HeaderElement[] { element };
        when(header.getElements()).thenReturn(elements);
        when(element.getName()).thenReturn("no-cache", "no-store");
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.cache, never()).set(Matchers.anyString(), Matchers.anyBoolean());
        verify(this.cache, times(2)).remove("jdoe::edit::P0000001");
    }

    @Test
    public void otherCacheHeadersIgnored() throws Exception
    {
        setupNeededComponents();
        when(this.client.execute(any(HttpPost.class))).thenReturn(this.response);
        when(this.response.getStatusLine()).thenReturn(this.status);
        when(this.status.getStatusCode()).thenReturn(HttpStatus.SC_OK);
        Header header = mock(Header.class);
        when(this.response.getLastHeader("Cache-Control")).thenReturn(header);
        HeaderElement element = mock(HeaderElement.class);
        HeaderElement[] elements = new HeaderElement[] { element };
        when(header.getElements()).thenReturn(elements);
        when(element.getName()).thenReturn("public");
        Assert.assertTrue(this.mocker.getComponentUnderTest().hasAccess(this.user, this.access, this.document));
        verify(this.cache).set("jdoe::edit::P0000001", true);
    }

    @Test
    public void expectedPriority() throws Exception
    {
        setupNeededComponents();
        Assert.assertEquals(500, this.mocker.getComponentUnderTest().getPriority());
    }

    private void setupNeededComponents() throws ComponentLookupException, CacheException
    {
        MockitoAnnotations.initMocks(this);

        ConfigurationSource configuration = this.mocker.getInstance(ConfigurationSource.class, "restricted");
        when(configuration.getProperty(RemoteAuthorizationModule.CONFIGURATION_KEY)).thenReturn(this.url);

        CacheFactory cf = this.mocker.getInstance(CacheFactory.class, "infinispan");
        when(cf.<Boolean>newCache(any(CacheConfiguration.class))).thenReturn(this.cache);
        ReflectionUtils.setFieldValue(this.mocker.getComponentUnderTest(), "client", this.client);

        PatientRepository repo = this.mocker.getInstance(PatientRepository.class);
        when(repo.getPatientById(this.document.toString())).thenReturn(this.patient);

        when(this.user.getUsername()).thenReturn("jdoe");
        when(this.patient.getId()).thenReturn("P0000001");
        when(this.patient.getExternalId()).thenReturn("P_1234");
        when(this.access.getName()).thenReturn("edit");
    }
}
