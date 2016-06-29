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
package org.wso2.carbon.certificate.mgt.core.service;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.certificate.mgt.core.dao.CertificateManagementDAOException;
import org.wso2.carbon.certificate.mgt.core.dto.CertificateResponse;
import org.wso2.carbon.certificate.mgt.core.dto.SCEPResponse;
import org.wso2.carbon.certificate.mgt.core.exception.KeystoreException;
import org.wso2.carbon.device.mgt.common.PaginationRequest;
import org.wso2.carbon.device.mgt.common.PaginationResult;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateManagementService {

    Certificate getCACertificate() throws KeystoreException;

    Certificate getRACertificate() throws KeystoreException;

    List<X509Certificate> getRootCertificates(byte[] ca, byte[] ra) throws KeystoreException;

    X509Certificate generateX509Certificate() throws KeystoreException;

    SCEPResponse getCACertSCEP() throws KeystoreException;

    byte[] getCACapsSCEP();

    byte[] getPKIMessageSCEP(InputStream inputStream) throws KeystoreException;

    X509Certificate generateCertificateFromCSR(PrivateKey privateKey, PKCS10CertificationRequest request,
                                               String issueSubject) throws KeystoreException;

    Certificate getCertificateByAlias(String alias) throws KeystoreException;

    boolean verifySignature(String headerSignature) throws KeystoreException;

    public CertificateResponse verifyPEMSignature(X509Certificate requestCertificate) throws KeystoreException;

    public CertificateResponse verifySubjectDN(String requestDN) throws KeystoreException;

    public X509Certificate extractCertificateFromSignature(String headerSignature) throws KeystoreException;

    String extractChallengeToken(X509Certificate certificate);

    X509Certificate getSignedCertificateFromCSR(String binarySecurityToken) throws KeystoreException;

    public CertificateResponse getCertificateBySerial(String serial) throws KeystoreException;

    public void saveCertificate(List<org.wso2.carbon.certificate.mgt.core.bean.Certificate> certificate)
            throws KeystoreException;

    public X509Certificate pemToX509Certificate(String pem) throws KeystoreException;

    public CertificateResponse retrieveCertificate(String serialNumber) throws CertificateManagementDAOException;

    public PaginationResult getAllCertificates(PaginationRequest request) throws CertificateManagementDAOException;

    boolean removeCertificate(String serialNumber) throws CertificateManagementDAOException;

    public List<CertificateResponse> getCertificates() throws CertificateManagementDAOException;

    public List<CertificateResponse> searchCertificates(String serialNumber) throws CertificateManagementDAOException;
}
