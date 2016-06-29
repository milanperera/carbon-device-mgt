/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.webapp.authenticator.framework.authorizer;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.device.mgt.common.permission.mgt.Permission;
import org.wso2.carbon.device.mgt.common.permission.mgt.PermissionManagementException;
import org.wso2.carbon.device.mgt.core.permission.mgt.PermissionManagerServiceImpl;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.webapp.authenticator.framework.Constants;
import org.wso2.carbon.webapp.authenticator.framework.authenticator.WebappAuthenticator;

import java.util.Properties;

/**
 * This class represents the methods that are used to authorize requests.
 */
public class PermissionAuthorizer {

    private static final Log log = LogFactory.getLog(PermissionAuthorizer.class);

    public WebappAuthenticator.Status authorize(Request request, Response response) {

        String requestUri = request.getRequestURI();
        String requestMethod = request.getMethod();

        if (requestUri == null || requestUri.isEmpty() || requestMethod == null || requestMethod.isEmpty()) {
            return WebappAuthenticator.Status.CONTINUE;
        }

        PermissionManagerServiceImpl registryBasedPermissionManager = PermissionManagerServiceImpl.getInstance();
        Properties properties = new Properties();
        properties.put("",requestUri);
        properties.put("",requestMethod);
        Permission requestPermission = null;
        try {
            requestPermission = registryBasedPermissionManager.getPermission(properties);
        } catch (PermissionManagementException e) {
            log.error(
                    "Error occurred while fetching the permission for URI : " + Encode.forJava(requestUri) + " ," +
                    " METHOD : " + requestMethod + ", msg = " + e.getMessage());
        }

        if (requestPermission == null) {
            if (log.isDebugEnabled()) {
                log.debug("Permission to request '" + Encode.forJava(requestUri) + "' is not defined in the configuration");
            }
            return WebappAuthenticator.Status.FAILURE;
        }

        String permissionString = requestPermission.getPath();

        // This is added temporarily until authentication works.
        // TODO remove below line.
        String username = "admin";
        // TODO uncomment this once the authentication works.
        //String username = CarbonContext.getThreadLocalCarbonContext().getUsername();

        boolean isUserAuthorized;
        try {
            isUserAuthorized = CarbonContext.getThreadLocalCarbonContext().getUserRealm().
                    getAuthorizationManager().isUserAuthorized(username, permissionString,
                    Constants.PermissionMethod.READ);
        } catch (UserStoreException e) {
            log.error("Error occurred while retrieving user store. " + e.getMessage());
            return WebappAuthenticator.Status.FAILURE;
        }

        if (isUserAuthorized) {
            return WebappAuthenticator.Status.SUCCESS;
        } else {
            return WebappAuthenticator.Status.FAILURE;
        }
    }

}
