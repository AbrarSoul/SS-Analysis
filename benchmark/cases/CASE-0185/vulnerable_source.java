/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc., Kohsuke Kawaguchi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.googlelogin;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeResponseUrl;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.Failure;
import hudson.remoting.Base64;
import hudson.util.HttpResponses;
import org.kohsuke.stapler.HttpRedirect;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

import java.io.IOException;
import java.io.Serializable;
import java.lang.IllegalArgumentException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * The state of the OAuth request.
 *
 * Verifies the validity of the response by comparing the state.
 */
public abstract class OAuthSession implements Serializable {

    private static final long serialVersionUID = 1438835558745081350L;

    private final String uuid = Base64.encode(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)).substring(0,20);
    /**
     * The url the user was trying to navigate to.
     */
    private final String from;

    /**
     * Where Google will redirect to once the scopes are approved by the user.
     */
    private final String redirectUrl;

    private final String domain;

    public OAuthSession(String from, String redirectUrl, String domain) {
        this.from = from;
        this.redirectUrl = redirectUrl;
        this.domain = domain;
    }

    /**
     * Starts the login session.
     */
    public HttpResponse doCommenceLogin(AuthorizationCodeFlow flow) throws IOException {
        AuthorizationCodeRequestUrl authorizationCodeRequestUrl = flow.newAuthorizationUrl().setState(uuid).setRedirectUri(redirectUrl);
        if (domain != null) {
            if (domain.contains(",")) {
                authorizationCodeRequestUrl.set("hd","*");
            } else {
                authorizationCodeRequestUrl.set("hd",domain);
            }
        }
        return new HttpRedirect(authorizationCodeRequestUrl.toString());
    }

    /**
     * When the identity provider is done with its thing, the user comes back here.
     */
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        if (request.getParameter("state") == null) {
            // user was not sent here by Google
            return HttpResponses.redirectToContextRoot();
        }
        StringBuffer buf = request.getRequestURL();
        if (request.getQueryString() != null) {
            buf.append('?').append(request.getQueryString());
        }
        try {
            AuthorizationCodeResponseUrl responseUrl = new AuthorizationCodeResponseUrl(buf.toString());
            if (! uuid.equals(responseUrl.getState())) {
                return HttpResponses.error(401, "State is invalid");
            }
            String code = responseUrl.getCode();
            if (responseUrl.getError() != null) {
                return HttpResponses.error(401, "Error from provider: " + code);
            } else if (code == null) {
                return HttpResponses.error(404, "Missing authorization code");
            } else {
                return onSuccess(code);
            }
        } catch (IllegalArgumentException e) {
            throw new Failure("Failed to login. Cannot parse URL.");
        }
    }

    /**
     * Where was the user trying to navigate to when they had to login?
     *
     * @return the url the user wants to reach
     */
    protected String getFrom() {
        return from;
    }

    protected abstract HttpResponse onSuccess(String authorizationCode) throws IOException;
}
