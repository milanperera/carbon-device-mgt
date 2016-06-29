/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * This backendServiceInvoker contains the wrappers for back end jaggary calls.
 */
var backendServiceInvoker = function () {
    var log = new Log("/app/modules/backend-service-invoker.js");
    var publicXMLHTTPInvokers = {};
    var privateMethods = {};
    var publicWSInvokers = {};
    var publicHTTPClientInvokers = {};
    var IS_OAUTH_ENABLED = true;
    var TOKEN_EXPIRED = "Access token expired";
    var TOKEN_INVALID = "Invalid input. Access token validation failed";
    var constants = require("/app/modules/constants.js");
    var tokenUtil = require("/app/modules/api-wrapper-util.js").apiWrapperUtil;
    var devicemgtProps = require('/app/conf/devicemgt-props.js').config();

    /**
     * This methoad reads the token pair from the session and return the access token.
     * If the token pair s not set in the session this will send a redirect to the login page.
     */
    privateMethods.getAccessToken = function () {
        var tokenPair = session.get(constants.ACCESS_TOKEN_PAIR_IDENTIFIER);
        if (tokenPair) {
            return tokenPair.accessToken;
        } else {
            return null;
        }
    };

    /**
     * This method add Oauth authentication header to outgoing XMLHTTP Requests if Oauth authentication is enabled.
     * @param method HTTP request type.
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     * @param count a counter which hold the number of recursive execution
     */
    privateMethods.execute = function (method, url, successCallback, errorCallback, payload, count, contentType, acceptType) {
        var xmlHttpRequest = new XMLHttpRequest();
        xmlHttpRequest.open(method, url);
        if(!contentType){
            contentType = constants.APPLICATION_JSON;
        }
        if(!acceptType){
            acceptType = constants.APPLICATION_JSON;
        }
        xmlHttpRequest.setRequestHeader(constants.CONTENT_TYPE_IDENTIFIER, contentType);
        xmlHttpRequest.setRequestHeader(constants.ACCEPT_IDENTIFIER, acceptType);
        xmlHttpRequest.setRequestHeader(constants.REFERER, String(privateMethods.getClientDomain()));
        if (IS_OAUTH_ENABLED) {
            var accessToken = privateMethods.getAccessToken();
            if (!accessToken) {
                response.sendRedirect(devicemgtProps["httpsURL"] + "/devicemgt/login");
            } else {
                xmlHttpRequest.setRequestHeader(constants.AUTHORIZATION_HEADER, constants.BEARER_PREFIX + accessToken);
            }
        }
        if (payload) {
            xmlHttpRequest.send(payload);
        } else {
            xmlHttpRequest.send();
        }

        if ((xmlHttpRequest.status >= 200 && xmlHttpRequest.status < 300) || xmlHttpRequest.status == 302) {
            if (xmlHttpRequest.responseText != null) {
                return successCallback(parse(xmlHttpRequest.responseText));
            } else {
                return successCallback({"status": xmlHttpRequest.status, "messageFromServer": "Operation Completed"});
            }
        } else if (xmlHttpRequest.status == 401 && (xmlHttpRequest.responseText == TOKEN_EXPIRED ||
                                                    xmlHttpRequest.responseText == TOKEN_INVALID ) && count < 5) {
            tokenUtil.refreshToken();
            return privateMethods.execute(method, url, successCallback, errorCallback, payload, (count + 1));
        } else if (xmlHttpRequest.status == 500) {
            return errorCallback(xmlHttpRequest);
        } else {
            return errorCallback(xmlHttpRequest);
        }
    };

    /**
     * This method add Oauth authentication header to outgoing XMLHTTP Requests if Oauth authentication is enabled.
     * @param method HTTP request type.
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    privateMethods.initiateXMLHTTPRequest = function (method, url, successCallback, errorCallback, payload, contentType, acceptType) {
        if (privateMethods.getAccessToken()) {
            return privateMethods.execute(method, url, successCallback, errorCallback, payload, 0, contentType, acceptType);
        }
    };

    /**
     * This method add Oauth authentication header to outgoing HTTPClient Requests if Oauth authentication is enabled.
     * @param method HTTP request type.
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    privateMethods.initiateHTTPClientRequest = function (method, url, successCallback, errorCallback, payload, contentType, acceptType) {
        var HttpClient = Packages.org.apache.commons.httpclient.HttpClient;
        var httpMethodObject;
        switch (method) {
            case constants.HTTP_POST:
                var PostMethod = Packages.org.apache.commons.httpclient.methods.PostMethod;
                httpMethodObject = new PostMethod(url);
                break;
            case constants.HTTP_PUT:
                var PutMethod = Packages.org.apache.commons.httpclient.methods.PutMethod;
                httpMethodObject = new PutMethod(url);
                break;
            case constants.HTTP_GET:
                var GetMethod = Packages.org.apache.commons.httpclient.methods.GetMethod;
                httpMethodObject = new GetMethod(url);
                break;
            case constants.HTTP_DELETE:
                var DeleteMethod = Packages.org.apache.commons.httpclient.methods.DeleteMethod;
                httpMethodObject = new DeleteMethod(url);
                break;
            default:
                throw new IllegalArgumentException("Invalid HTTP request type: " + method);
        }
        var Header = Packages.org.apache.commons.httpclient.Header;
        var header = new Header();
        header.setName(constants.CONTENT_TYPE_IDENTIFIER);
        header.setValue(contentType);
        httpMethodObject.addRequestHeader(header);
        header = new Header();
        header.setName(constants.ACCEPT_IDENTIFIER);
        header.setValue(acceptType);
        httpMethodObject.addRequestHeader(header);
        header = new Header();
        header.setName(constants.REFERER);
        header.setValue(String(privateMethods.getClientDomain()));
        httpMethodObject.addRequestHeader(header);
        if (IS_OAUTH_ENABLED) {
            var accessToken = privateMethods.getAccessToken();
            if (accessToken) {
                header = new Header();
                header.setName(constants.AUTHORIZATION_HEADER);
                header.setValue(constants.BEARER_PREFIX + accessToken);
                httpMethodObject.addRequestHeader(header);
            } else {
                response.sendRedirect(devicemgtProps["httpsURL"] + "/devicemgt/login");
            }

        }
        if (payload) {
            var stringRequestEntity = new StringRequestEntity(stringify(payload));
            httpMethodObject.setRequestEntity(stringRequestEntity);
        }
        var client = new HttpClient();
        try {
            client.executeMethod(httpMethodObject);
            var status = httpMethodObject.getStatusCode();
            if (status == 200) {
                var responseContentDispositionHeader = httpMethodObject.getResponseHeader(constants.CONTENT_DISPOSITION_IDENTIFIER);
                if (responseContentDispositionHeader) {
                    return successCallback(httpMethodObject.getResponseBodyAsStream(), httpMethodObject.getResponseHeaders());
                } else {
                    return successCallback(httpMethodObject.getResponseBody());
                }
            } else {
                return errorCallback(httpMethodObject.getResponseBody());
            }
        } catch (e) {
            return errorCallback(response);
        } finally {
            httpMethodObject.releaseConnection();
        }
    };

    /**
     * This method add Oauth authentication header to outgoing WS Requests if Oauth authentication is enabled.
     * @param action
     * @param endpoint service end point to be triggered.
     * @param payload soap payload which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     * @param soapVersion soapVersion which need to used.
     */
    privateMethods.initiateWSRequest = function (action, endpoint, successCallback, errorCallback, soapVersion, payload) {
        var ws = require('ws');
        var wsRequest = new ws.WSRequest();
        var options = [];
        if (IS_OAUTH_ENABLED) {
            var accessToken = privateMethods.getAccessToken();
            if (accessToken) {
                var authenticationHeaderName = String(constants.AUTHORIZATION_HEADER);
                var authenticationHeaderValue = String(constants.BEARER_PREFIX + accessToken);
                var headers = [];
                var oAuthAuthenticationData = {};
                oAuthAuthenticationData.name = authenticationHeaderName;
                oAuthAuthenticationData.value = authenticationHeaderValue;
                headers.push(oAuthAuthenticationData);

                var referrerData = {};
                referrerData.name = constants.REFERER;
                referrerData.value = String(privateMethods.getClientDomain());
                headers.push(referrerData);

                options.HTTPHeaders = headers;
            } else {
                response.sendRedirect(devicemgtProps["httpsURL"] + "/devicemgt/login");
            }
        }
        options.useSOAP = soapVersion;
        options.useWSA = constants.WEB_SERVICE_ADDRESSING_VERSION;
        options.action = action;
        var wsResponse;
        try {
            wsRequest.open(options, endpoint, false);
            if (payload) {
                wsRequest.send(payload);
            } else {
                wsRequest.send();
            }
            wsResponse = wsRequest.responseE4X;
        } catch (e) {
            return errorCallback(e);
        }
        return successCallback(wsResponse);
    };

    /**
     * This method invokes return initiateXMLHttpRequest for get calls
     * @param url target url.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicXMLHTTPInvokers.get = function (url, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateXMLHTTPRequest(constants.HTTP_GET, url, successCallback, errorCallback, contentType, acceptType);
    };

    /**
     * This method invokes return initiateXMLHttpRequest for post calls
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicXMLHTTPInvokers.post = function (url, payload, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateXMLHTTPRequest(constants.HTTP_POST, url, successCallback, errorCallback, payload, contentType, acceptType);
    };

    /**
     * This method invokes return initiateXMLHttpRequest for put calls
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicXMLHTTPInvokers.put = function (url, payload, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateXMLHTTPRequest(constants.HTTP_PUT, url, successCallback, errorCallback, payload, contentType, acceptType);
    };

    /**
     * This method invokes return initiateXMLHttpRequest for delete calls
     * @param url target url.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicXMLHTTPInvokers.delete = function (url, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateXMLHTTPRequest(constants.HTTP_DELETE, url, successCallback, errorCallback, contentType, acceptType);
    };

    /**
     * This method invokes return initiateWSRequest for soap calls
     * @param endpoint service end point to be triggered.
     * @param payload soap payload which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     * @param soapVersion soapVersion which need to used.
     */
    publicWSInvokers.soapRequest = function (action, endpoint, payload, successCallback, errorCallback, soapVersion) {
        return privateMethods.initiateWSRequest(action, endpoint, successCallback, errorCallback, soapVersion, payload);
    };


    /**
     * This method invokes return initiateHTTPClientRequest for get calls
     * @param url target url.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicHTTPClientInvokers.get = function (url, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateHTTPClientRequest(constants.HTTP_GET, url, successCallback, errorCallback, null, contentType, acceptType);
    };

    /**
     * This method invokes return initiateHTTPClientRequest for post calls
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicHTTPClientInvokers.post = function (url, payload, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.
            initiateHTTPClientRequest(constants.HTTP_POST, url, successCallback, errorCallback, payload, contentType, acceptType);
    };

    /**
     * This method invokes return initiateHTTPClientRequest for put calls
     * @param url target url.
     * @param payload payload/data which need to be send.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicHTTPClientInvokers.put = function (url, payload, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateHTTPClientRequest(constants.HTTP_PUT, url, successCallback, errorCallback, payload, contentType, acceptType);
    };

    /**
     * This method invokes return initiateHTTPClientRequest for delete calls
     * @param url target url.
     * @param successCallback a function to be called if the respond if successful.
     * @param errorCallback a function to be called if en error is reserved.
     */
    publicHTTPClientInvokers.delete = function (url, successCallback, errorCallback, contentType, acceptType) {
        return privateMethods.initiateHTTPClientRequest(constants.HTTP_DELETE, url, successCallback, errorCallback, contentType, acceptType);
    };

    /**
     * This method fetch the current logged user from the session and returns
     * the tenant domain name of the user
     * @returns {tenantDomain}
     */
    privateMethods.getClientDomain = function () {
        var user = session.get(constants.USER_SESSION_KEY);
        return user.domain;
    }

    var publicInvokers = {};
    publicInvokers.XMLHttp = publicXMLHTTPInvokers;
    publicInvokers.WS = publicWSInvokers;
    publicInvokers.HttpClient = publicHTTPClientInvokers;
    return publicInvokers;
}();