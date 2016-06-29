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

var apiWrapperUtil = function () {
    var module = {};
    var tokenUtil = require("/app/modules/util.js").util;
    var constants = require("/app/modules/constants.js");
    var devicemgtProps = require('/app/conf/devicemgt-props.js').config();
    var log = new Log("/app/modules/api-wrapper-util.js");

    module.refreshToken = function () {
        var tokenPair = session.get(constants.ACCESS_TOKEN_PAIR_IDENTIFIER);
        var clientData = session.get(constants.ENCODED_CLIENT_KEYS_IDENTIFIER);
        tokenPair = tokenUtil.refreshToken(tokenPair, clientData);
        session.put(constants.ACCESS_TOKEN_PAIR_IDENTIFIER, tokenPair);
    };
    module.setupAccessTokenPair = function (type, properties) {
        var tokenPair;
        var clientData = tokenUtil.getDyanmicCredentials(properties);
        var jwtToken = tokenUtil.getTokenWithJWTGrantType(clientData);
        clientData = tokenUtil.getTenantBasedAppCredentials(properties.username, jwtToken);
        var encodedClientKeys = tokenUtil.encode(clientData.clientId + ":" + clientData.clientSecret);
        session.put(constants.ENCODED_CLIENT_KEYS_IDENTIFIER, encodedClientKeys);
        if (type == constants.GRANT_TYPE_PASSWORD) {
            var scopes = devicemgtProps.scopes;
            var scope = "";
            scopes.forEach(function(entry) {
                scope += entry + " ";
            });
            tokenPair =
                tokenUtil.getTokenWithPasswordGrantType(properties.username, encodeURIComponent(properties.password),
                    encodedClientKeys, scope);
        } else if (type == constants.GRANT_TYPE_SAML) {
            tokenPair = tokenUtil.
            getTokenWithSAMLGrantType(properties.samlToken, encodedClientKeys, "PRODUCTION");
        }
        session.put(constants.ACCESS_TOKEN_PAIR_IDENTIFIER, tokenPair);
    };
    return module;
}();