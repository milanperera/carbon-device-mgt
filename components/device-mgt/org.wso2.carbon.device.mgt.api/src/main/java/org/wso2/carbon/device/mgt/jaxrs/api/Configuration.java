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

package org.wso2.carbon.device.mgt.jaxrs.api;

import io.swagger.annotations.Api;
import org.wso2.carbon.device.mgt.common.configuration.mgt.TenantConfiguration;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;

/**
 * General Tenant Configuration REST-API implementation.
 * All end points support JSON, XMl with content negotiation.
 */
@Api(value = "Configuration", description = "General Tenant Configuration implementation")
@SuppressWarnings("NonJaxWsWebServices")
@Produces({ "application/json", "application/xml" })
@Consumes({ "application/json", "application/xml" })
public interface Configuration {

    @POST
    Response saveTenantConfiguration(TenantConfiguration configuration);

    @GET
    Response getConfiguration();

    @PUT
    Response updateConfiguration(TenantConfiguration configuration);

}