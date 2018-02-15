/*
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.wso2.carbon.device.application.mgt.common.services;

import org.wso2.carbon.device.application.mgt.common.*;
import org.wso2.carbon.device.application.mgt.common.exception.ApplicationManagementException;
import org.wso2.carbon.device.application.mgt.common.exception.LifecycleManagementException;
import org.wso2.carbon.device.mgt.core.dao.DeviceManagementDAOException;

import java.util.List;

/**
 * This interface manages the application creation, deletion and editing of the application.
 */
public interface ApplicationManager {

    /**
     * Creates an application.
     *
     * @param application Application that need to be created.
     * @return Created application
     * @throws ApplicationManagementException Application Management Exception
     */
    Application createApplication(Application application) throws ApplicationManagementException;

    /**
     * Updates an already existing application.
     *
     * @param application Application that need to be updated.
     * @return Updated Application
     * @throws ApplicationManagementException Application Management Exception
     */
    Application editApplication(Application application) throws ApplicationManagementException;

    /**
     * Delete an application identified by the unique ID.
     *
     * @param applicationId ID for tha application
     * @throws ApplicationManagementException Application Management Exception
     */
    void deleteApplication(int applicationId) throws ApplicationManagementException;

    /**
     * Delete an application identified by the unique ID.
     *
     * @param applicationId ID of tha application
     * @param releaseUuid UUID of tha application release
     * @throws ApplicationManagementException Application Management Exception
     */
    void deleteApplicationRelease(int applicationId, String releaseUuid) throws ApplicationManagementException;

    /**
     * To get the applications based on the search filter.
     *
     * @param filter Search filter
     * @return Applications that matches the given filter criteria.
     * @throws ApplicationManagementException Application Management Exception
     */
    ApplicationList getApplications(Filter filter) throws ApplicationManagementException;

    /**
     * To get the applications based on the search filter.
     *
     * @param appId id of the application
     * @return Application release which is published and release of the Application(appId).
     * @throws ApplicationManagementException Application Management Exception
     */
    String getUuidOfLatestRelease(int appId) throws ApplicationManagementException;


    /**
     * To change the lifecycle of the Application.
     *
     * @param applicationUuid     UUID of the Application
     * @param lifecycleIdentifier New life-cycle that need to be changed.
     * @throws ApplicationManagementException Application Management Exception.
     */
    void changeLifecycle(String applicationUuid, String lifecycleIdentifier) throws
            ApplicationManagementException;

    /**
     * To get the next possible life-cycle states for the application.
     *
     * @param applicationUUID UUID of the application.
     * @return the List of possible states
     * @throws ApplicationManagementException Application Management Exception
     */
    List<LifecycleStateTransition> getLifeCycleStates(String applicationUUID)
            throws ApplicationManagementException;

    /**
     * To get Application with the given UUID.
     *
     * @param appType type of the Application
     * @param appName name of the Application
     * @return the Application identified by the UUID
     * @throws ApplicationManagementException Application Management Exception.
     */
    Application getApplication(String appType, String appName) throws ApplicationManagementException;

    /**
     * To get Application with the given UUID.
     *
     * @param applicationId Id of the Application
     * @return the Application identified by the application id
     * @throws ApplicationManagementException Application Management Exception.
     */
    Application getApplicationById(int applicationId) throws ApplicationManagementException;


    /**
     * To get Application with the given UUID.
     *
     * @param appId ID of the Application
     * @return the boolean value, whether application exist or not
     * @throws ApplicationManagementException Application Management Exception.
     */
    Boolean verifyApplicationExistenceById(int appId) throws ApplicationManagementException;

    /**
     * To get Application with the given UUID.
     *
     * @return the boolean value, whether user has assigned unrestricted roles to access the application
     * * @throws ApplicationManagementException Application Management Exception.
     */
    Boolean isUserAllowable(List<UnrestrictedRole> unrestrictedRoles, String userName) throws ApplicationManagementException;

    /**
     * To get all the releases of a particular Application.
     *
     * @param applicationId ID of the Application to get all the releases.
     * @return the List of the Application releases related with the particular Application.
     * @throws ApplicationManagementException Application Management Exception.
     */
    List<ApplicationRelease> getReleases(int applicationId) throws ApplicationManagementException;

    LifecycleState getLifecycleState(int appReleaseId, String applicationUuid) throws LifecycleManagementException;

    void addLifecycleState(int applicationId, String applicationUuid, LifecycleState state) throws LifecycleManagementException;


}