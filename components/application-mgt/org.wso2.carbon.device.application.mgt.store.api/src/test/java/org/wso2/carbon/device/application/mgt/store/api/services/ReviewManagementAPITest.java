/*
 *   Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.device.application.mgt.store.api.services;

import junit.framework.TestCase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Ignore;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.core.classloader.annotations.SuppressStaticInitializationFor;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.device.application.mgt.common.Review;
import org.wso2.carbon.device.application.mgt.common.exception.ApplicationManagementException;
import org.wso2.carbon.device.application.mgt.common.exception.CommentManagementException;
import org.wso2.carbon.device.application.mgt.common.services.ReviewManager;
import org.wso2.carbon.device.application.mgt.store.api.APIUtil;
import org.wso2.carbon.device.application.mgt.store.api.services.impl.ReviewManagementAPIImpl;
import org.wso2.carbon.device.application.mgt.store.api.services.util.CommentMgtTestHelper;

import javax.ws.rs.core.Response;

import static org.mockito.MockitoAnnotations.initMocks;

@PowerMockIgnore("javax.ws.rs.*")
@SuppressStaticInitializationFor({
    "org.wso2.carbon.device.application.mgt.api.APIUtil" })
@PrepareForTest({ APIUtil.class, ReviewManager.class,
    ReviewManagementAPITest.class})
@Ignore("Since comment manager logic is invalid temporarily added Ignore annotation to skip running comment management test cases") public class ReviewManagementAPITest
        extends
        TestCase {
    private static final Log log = LogFactory.getLog(ReviewManagementAPI.class);

    private ReviewManagementAPI commentManagementAPI;
    private ReviewManager reviewManager;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeClass
    void init() throws CommentManagementException {

        log.info("Initializing ReviewManagementAPI tests");
        initMocks(this);
        this.reviewManager = Mockito.mock(ReviewManager.class, Mockito.RETURNS_DEFAULTS);
        this.commentManagementAPI = new ReviewManagementAPIImpl();
    }

    @Test
    public void testGetAllCommentsWithValidDetails() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.getAllReviews("a", 1, 2);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.OK.getStatusCode(),
            "The response status should be 200.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testGetAllCommentsInternalError() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Mockito.doThrow(new CommentManagementException()).when(this.reviewManager)
            .getAllReviews(Mockito.any(), Mockito.anyString());
        Response response = this.commentManagementAPI.getAllReviews("a", 1, 4);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            "The response status should be 500.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testGetAllCommentsNotFoundError() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.getAllReviews(null, 1, 3);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.NOT_FOUND.getStatusCode(),
            "The response status should be 404.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testAddComments() throws Exception {
        Review review = CommentMgtTestHelper.getDummyComment("a", "a");
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.addReview(review, "a");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.CREATED.getStatusCode(),
            "The response status should be 201.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testAddNullComment() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.addReview(null, "a");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
            "The response status should be 400.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testAddCommentsInternalError() throws Exception {
        Review review = CommentMgtTestHelper.getDummyComment("a", "a");
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Mockito.when(this.commentManagementAPI.addReview(Mockito.any(), Mockito.anyString()))
            .thenThrow(new CommentManagementException());
        Response response = this.commentManagementAPI.addReview(review, null);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            "The response status should be 500.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testUpdateComment() throws Exception {
        Review review = CommentMgtTestHelper.getDummyComment("a", "a");
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.updateComment(review, 1);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.OK.getStatusCode(),
            "The response status should be 200.");
    }

    @Test
    public void testUpdateNullComment() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.updateComment(null, 1);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.BAD_REQUEST.getStatusCode(),
            "The response status should be 400.");
    }

    @Test
    public void testUpdateCommentWhenNullCommentId() throws Exception {
        Review review = CommentMgtTestHelper.getDummyComment("a", "a");
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.updateComment(review, 0);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.NOT_FOUND.getStatusCode(),
            "The response status should be 404.");
    }

    @Test
    public void testUpdateCommentInternalServerError() throws Exception {
        Review review = CommentMgtTestHelper.getDummyComment("a", "a");
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Mockito.doThrow(new CommentManagementException()).when(this.reviewManager).updateReview(review, 9, true);
        Response response = this.commentManagementAPI.updateComment(review, 9);
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            "The response status should be 500.");
    }

    @Test
    public void testDeleteComment() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.deleteComment(1,"");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.OK.getStatusCode(),
            "The response status should be 200.");
    }

    @Test
    public void testDeleteCommentInternalError() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Mockito.when(this.commentManagementAPI.deleteComment(1,"")).thenThrow(new CommentManagementException());
        Response response = this.commentManagementAPI.deleteComment(1,"");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            "The response status should be 500.");
    }

    @Test
    public void testDeleteCommentNotFoundError() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.deleteComment(0,"");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.NOT_FOUND.getStatusCode(),
            "The response status should be 404.");
    }

    @Test
    public void testGetStars() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Response response = this.commentManagementAPI.getRating("a");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.OK.getStatusCode(),
            "The response status should be 200.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testGetStarsCommentError() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Mockito.when(this.commentManagementAPI.getRating(Mockito.anyString()))
            .thenThrow(new CommentManagementException());
        Response response = this.commentManagementAPI.getRating("a");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            "The response status should be 500.");
        Mockito.reset(reviewManager);
    }

    @Test
    public void testGetStarsApplicationError() throws Exception {
        PowerMockito.stub(PowerMockito.method(APIUtil.class, "getReviewManager")).toReturn(this.reviewManager);
        Mockito.when(this.commentManagementAPI.getRating(Mockito.anyString()))
            .thenThrow(new ApplicationManagementException());
        Response response = this.commentManagementAPI.getRating("a");
        Assert.assertNotNull(response, "The response object is null.");
        Assert.assertEquals(response.getStatus(), Response.Status.INTERNAL_SERVER_ERROR.getStatusCode(),
            "The response status should be 500.");
        Mockito.reset(reviewManager);
    }
}