/*
*  Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*
*/
package org.wso2.carbon.device.application.mgt.core.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.device.application.mgt.common.Rating;
import org.wso2.carbon.device.application.mgt.common.Review;
import org.wso2.carbon.device.application.mgt.common.PaginationRequest;
import org.wso2.carbon.device.application.mgt.common.PaginationResult;
import org.wso2.carbon.device.application.mgt.common.exception.CommentManagementException;
import org.wso2.carbon.device.application.mgt.common.exception.DBConnectionException;
import org.wso2.carbon.device.application.mgt.common.exception.TransactionManagementException;
import org.wso2.carbon.device.application.mgt.common.services.*;
import org.wso2.carbon.device.application.mgt.core.dao.ApplicationReleaseDAO;
import org.wso2.carbon.device.application.mgt.core.dao.ReviewDAO;
import org.wso2.carbon.device.application.mgt.core.dao.common.ApplicationManagementDAOFactory;
import org.wso2.carbon.device.application.mgt.core.dao.common.Util;
import org.wso2.carbon.device.application.mgt.core.exception.ApplicationManagementDAOException;
import org.wso2.carbon.device.application.mgt.core.internal.DataHolder;
import org.wso2.carbon.device.application.mgt.core.util.ConnectionManagerUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.sql.SQLException;
import java.util.List;
import java.util.TreeMap;

/**
 * This class is the default implementation for the Managing the comments.
 */
public class ReviewManagerImpl implements ReviewManager {

    private static final Log log = LogFactory.getLog(ReviewManagerImpl.class);
    private ReviewDAO reviewDAO;
    private ApplicationReleaseDAO applicationReleaseDAO;

    public ReviewManagerImpl() {
        initDataAccessObjects();
    }

    private void initDataAccessObjects() {
        this.reviewDAO = ApplicationManagementDAOFactory.getCommentDAO();
        this.applicationReleaseDAO = ApplicationManagementDAOFactory.getApplicationReleaseDAO();
    }

    @Override
    public boolean addReview(Review review, int appId, int appReleaseId) throws CommentManagementException {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(true);
        String username = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        boolean isSuccess;
        try {
            ConnectionManagerUtil.beginDBTransaction();
            Review existingReview = reviewDAO.isExistReview(appId, appReleaseId, username, tenantId);
            if (existingReview != null && review.getRating() > 0 && review.getRating() != existingReview.getRating()) {
                Runnable task = () -> {
                    try {
                        if (calculateRating(review.getRating(), existingReview.getRating()) <= 0.0) {
                            log.error("Application release rating updating task is failed");
                        }
                    } catch (CommentManagementException e) {
                        //                        todo
                        log.error("comment management error occured");
                    }
                };
                new Thread(task).start();
                isSuccess = updateReview(review, existingReview.getId(), false);
                if (isSuccess) {
                    ConnectionManagerUtil.commitDBTransaction();
                } else {
                    ConnectionManagerUtil.rollbackDBTransaction();
                }
            } else {
                if (review.getRating()>0){
                    Runnable task = () -> {
                        try {
                            if (calculateRating(review.getRating(), -12345) <= 0.0) {
                                log.error("Application release rating inserting task is failed");
                            }
                        } catch (CommentManagementException e) {
                            //                            todo
                            log.error("comment management error occured");
                        }
                    };
                    new Thread(task).start();
                }
                review.setUsername(username);
                isSuccess = this.reviewDAO.addReview(review, appId, appReleaseId, tenantId);
                if (isSuccess) {
                    ConnectionManagerUtil.commitDBTransaction();
                } else {
                    ConnectionManagerUtil.rollbackDBTransaction();
                }
            }
            return isSuccess;
        } catch (DBConnectionException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "DB Connection error occurs ,Review for application with app id: " + appId + " and app release id: "
                            + appReleaseId + " is failed", e);
        } catch (SQLException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "SQL Exception occurs,Review for application with app id:" + appId + " and app release id:"
                            + appReleaseId + " is failed", e);
        } catch (TransactionManagementException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "Transaction Management Exception occurs,Review for application with app id:" + appId
                            + " and app release id:" + appReleaseId + " is failed ", e);
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
    }

    @Override
    public boolean updateReview(Review review, int reviewId, boolean checkExistence)
            throws CommentManagementException {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(true);
        String username = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        Review existingReview;
        boolean isSuccess;
        if (log.isDebugEnabled()) {
            log.debug("Review updating request is received for the review id " + reviewId);
        }
        try {
            ConnectionManagerUtil.openDBConnection();
            if (!username.equals(review.getUsername())) {
                throw new CommentManagementException(
                        "User " + review.getUsername() + "doesn't match with the logged in user: " + username);
            }
            if (checkExistence) {
                existingReview = this.reviewDAO.getComment(reviewId);
                if (existingReview != null) {
                    if (review.getRating() > 0 && review.getRating() != existingReview.getRating()) {
                        Runnable task = () -> {
                            try {
                                if (calculateRating(review.getRating(), existingReview.getRating()) <= 0.0) {
                                    log.error("Application release review updating task is failed");
                                }
                            } catch (CommentManagementException e) {
                                //                                todo
                                log.error("error");
                            }
                        };
                        new Thread(task).start();
                    }
                } else {
                    throw new CommentManagementException("Couldn't find a review for review id: " + reviewId);
                }
            }
            ConnectionManagerUtil.beginDBTransaction();
            isSuccess = this.reviewDAO.updateReview(review, reviewId, tenantId);
            if (isSuccess) {
                ConnectionManagerUtil.commitDBTransaction();
            } else {
                ConnectionManagerUtil.rollbackDBTransaction();
            }
            return isSuccess;
        } catch (SQLException e) {
            throw new CommentManagementException("SQL Error occurs updating review with review id " + reviewId + ".",
                    e);
        } catch (DBConnectionException e) {
            throw new CommentManagementException(
                    "DB Connection error occurs updating review with review id " + reviewId + ".", e);
        } catch (TransactionManagementException e) {
            throw new CommentManagementException(
                    "Transaction management error occurs when updating review with review id " + reviewId + ".", e);
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
    }

    @Override
    public PaginationResult getAllReviews(PaginationRequest request, String uuid) throws CommentManagementException {
        PaginationResult paginationResult = new PaginationResult();
        int numOfComments;
        List<Review> reviews;
        if (log.isDebugEnabled()) {
            log.debug("get all reviews of the application release" + uuid);
        }
        try {
            ConnectionManagerUtil.openDBConnection();
            reviews = this.reviewDAO.getAllComments(uuid, Util.validateCommentListPageSize(request));
            numOfComments = reviews.size();
            paginationResult.setData(reviews);
            if (numOfComments > 0) {
                paginationResult.setRecordsFiltered(numOfComments);
                paginationResult.setRecordsTotal(numOfComments);
            } else {
                paginationResult.setRecordsFiltered(0);
                paginationResult.setRecordsTotal(0);
            }
            return paginationResult;
        } catch (DBConnectionException e) {
            throw new CommentManagementException(
                    "DB Connection error occurs , while getting reviews of application release UUID: " + uuid, e);
        } catch (SQLException e) {
            throw new CommentManagementException(
                    "Error occured in the data layer, while getting reviews of application release UUID: " + uuid, e);
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
    }

    @Override
    public Review getReview(int commentId) throws CommentManagementException {
        PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(true);
        Review review;
        if (log.isDebugEnabled()) {
            log.debug("Review retrieval request is received for the review id " + commentId);
        }
        try {
            ConnectionManagerUtil.openDBConnection();
            review = this.reviewDAO.getComment(commentId);
        } catch (DBConnectionException e) {
            throw new CommentManagementException(
                    "DB Connection error occurs ,Review with review id " + commentId + "cannot get.", e);
        } catch (SQLException e) {
            throw new CommentManagementException(
                    "SQL Exception occurs,Review with review id " + commentId + "cannot get.", e);
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
        return review;
    }

    @Override
    public void deleteReview(String loggedInUser, int commentId) throws CommentManagementException {
        Review existingReview;
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId(true);
        String username = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
        try {
            if (!loggedInUser.equals(username) && !isAdminUser(username, tenantId, CarbonConstants.UI_ADMIN_PERMISSION_COLLECTION)){
                throw new CommentManagementException(
                        "You don't have permission to delete the review. Please contact the administrator. Review Id: "
                                + commentId);
            }
            existingReview = getReview(commentId);
            if (existingReview == null) {
                throw new CommentManagementException(
                        "Cannot delete a non-existing review for the application with review id" + commentId);
            }
            Runnable task = () -> {
                try {
                    if (calculateRating(0, existingReview.getRating()) <= 0.0) {
                        log.error("Application release review updating task is failed");
                    }
                } catch (CommentManagementException e) {
                    //                    todo
                    log.error("error occured");
                }
            };
            new Thread(task).start();
            ConnectionManagerUtil.beginDBTransaction();
            this.reviewDAO.deleteComment(commentId);
            ConnectionManagerUtil.commitDBTransaction();
        } catch (DBConnectionException e) {
            throw new CommentManagementException(
                    "DB Connection error occurs deleting review with review id " + commentId + ".", e);
        } catch (SQLException e) {
            throw new CommentManagementException("SQL error occurs deleting review with review id " + commentId + ".",
                    e);
        } catch (TransactionManagementException e) {
            throw new CommentManagementException(
                    "Transaction Management Exception occurs deleting review with review id " + commentId + ".", e);
        } catch (UserStoreException e) {
            throw new CommentManagementException(
                    "User-store exception while checking whether the user " + username + " of tenant " + tenantId
                            + " has the publisher permission");
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
    }

    @Override
    public Rating getRating(String appReleaseUuuid) throws CommentManagementException{
        //todo
        int appReleaseId = 0;
        try {
            ConnectionManagerUtil.openDBConnection();
            Rating rating = this.applicationReleaseDAO.getRating(appReleaseId);
            if (rating == null) {
                throw new CommentManagementException("Couldn't find rating for application release id: " + appReleaseId
                        + ". Please check the existence of the application relese");
            }

            List<Integer> ratingValues = this.reviewDAO.getAllRatingValues(appReleaseUuuid);
            TreeMap<Integer, Integer> ratingVariety = rating.getRatingVariety();
            for (Integer ratingVal : ratingValues) {
                if (ratingVariety.containsKey(ratingVal)) {
                    ratingVariety.replace(ratingVal, ratingVariety.get(ratingVal) + 1);
                } else {
                    ratingVariety.put(ratingVal, 1);
                }
            }
            rating.setRatingVariety(ratingVariety);
            return rating;
        } catch (ApplicationManagementDAOException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "Error occured while updated the rating value of the application release id: " + appReleaseId
                            + " can not get.", e);
        } catch (DBConnectionException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "DB Connection error occured while updated the rating value of the application release id: " + appReleaseId
                            + " can not get.", e);
        } catch (SQLException e) {
            throw new CommentManagementException(
                    "DB Connection error occured while updated the rating value of the application release id: " + appReleaseId
                            + " can not get.", e);
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
    }

    private double calculateRating(int newRatingVal, int oldRatingVal) throws CommentManagementException {
        //        todo need to pass app release id
        int appReleaseId = 0;
        try {
            ConnectionManagerUtil.beginDBTransaction();
            Rating rating = this.applicationReleaseDAO.getRating(appReleaseId);
            if (rating == null) {
                throw new CommentManagementException(
                        "Couldn't find rating for application release id: " + appReleaseId);
            }
            double updatedRating;
            int numOfUsers = rating.getNoOfUsers();
            double currentRating = rating.getRatingValue() * numOfUsers;
            if (oldRatingVal == -12345) {
                updatedRating = (currentRating + newRatingVal) / (numOfUsers + 1);
                this.applicationReleaseDAO.updateRatingValue(appReleaseId, updatedRating, numOfUsers + 1);
            } else if ( newRatingVal == 0){
                updatedRating = (currentRating - newRatingVal) / (numOfUsers - 1);
                this.applicationReleaseDAO.updateRatingValue(appReleaseId, updatedRating, numOfUsers - 1);
            } else{
                double tmpVal;
                tmpVal = currentRating - oldRatingVal;
                updatedRating = (tmpVal + newRatingVal) / numOfUsers;
                this.applicationReleaseDAO.updateRatingValue(appReleaseId, updatedRating, numOfUsers );
            }
            ConnectionManagerUtil.commitDBTransaction();
            return updatedRating;
        } catch (ApplicationManagementDAOException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "Error occured while updated the rating value of the application release id: " + appReleaseId
                            + " can not get.", e);
        } catch (TransactionManagementException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "Transaction Management Exception occured while updated the rating value of the application release id: " + appReleaseId
                            + " can not get.", e);
        } catch (DBConnectionException e) {
            ConnectionManagerUtil.rollbackDBTransaction();
            throw new CommentManagementException(
                    "DB Connection error occured while updated the rating value of the application release id: " + appReleaseId
                            + " can not get.", e);
        } finally {
            ConnectionManagerUtil.closeDBConnection();
        }
    }

    /**
     * To check whether current user has the permission to do some secured operation.
     *
     * @param username   Name of the User.
     * @param tenantId   ID of the tenant.
     * @param permission Permission that need to be checked.
     * @return true if the current user has the permission, otherwise false.
     * @throws UserStoreException UserStoreException
     */
    private boolean isAdminUser(String username, int tenantId, String permission) throws UserStoreException {
        UserRealm userRealm = DataHolder.getInstance().getRealmService().getTenantUserRealm(tenantId);
        return userRealm != null && userRealm.getAuthorizationManager() != null && userRealm.getAuthorizationManager()
                .isUserAuthorized(MultitenantUtils.getTenantAwareUsername(username), permission,
                        CarbonConstants.UI_PERMISSION_ACTION);
    }
}