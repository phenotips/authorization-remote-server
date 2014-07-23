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

import org.phenotips.security.authorization.AuthorizationModule;

import org.xwiki.cache.CacheException;
import org.xwiki.cache.CacheFactory;
import org.xwiki.cache.config.CacheConfiguration;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.Right;
import org.xwiki.test.mockito.MockitoComponentMockingRule;
import org.xwiki.users.User;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;

import static org.mockito.Matchers.any;
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
    private Right right;

    @Mock
    private DocumentReference doc;

    private String url = "http://host.net/checkAuthorization";

    @Test(expected = InitializationException.class)
    public void noConfigurationThrowsInitializationException() throws Throwable
    {
        try {
            this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc);
        } catch (ComponentLookupException ex) {
            Assert.assertTrue(ex.getCause().getMessage().contains("requires a valid URL to be configured"));
            throw ex.getCause();
        }
    }

    @Ignore
    @Test(expected = InitializationException.class)
    public void invalidConfigurationThrowsInitializationException() throws Throwable
    {
        ConfigurationSource configuration = this.mocker.getInstance(ConfigurationSource.class, "restricted");
        when(configuration.getProperty(RemoteAuthorizationModule.CONFIGURATION_KEY)).thenReturn("NotAnURL");
        try {
            this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc);
        } catch (ComponentLookupException ex) {
            Assert.assertEquals("Invalid URL configured for RemoteAuthorizationModule: NotAnURL",
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
            this.mocker.getComponentUnderTest().hasAccess(this.user, this.right, this.doc);
        } catch (ComponentLookupException ex) {
            Assert.assertEquals("Failed to create authorization cache: Bad Cache", ex.getCause().getMessage());
            throw ex.getCause();
        }
    }
}
