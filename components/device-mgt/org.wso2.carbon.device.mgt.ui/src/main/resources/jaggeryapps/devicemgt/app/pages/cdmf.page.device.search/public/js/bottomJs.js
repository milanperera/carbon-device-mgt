/*
 Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 WSO2 Inc. licenses this file to you under the Apache License,
 Version 2.0 (the "License"); you may not use this file except
 in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 either express or implied. See the License for the
 specific language governing permissions and limitations
 under the License.
 */

var removeCustomParam = function () {
    $(this).parent().parent().remove();
};

/**
 * Following function would execute
 * when a user clicks on the list item
 * initial mode and with out select mode.
 */
function InitiateViewOption() {
        $(location).attr('href', $(this).data("url"));
}

$("#back-to-search").click(function () {
    $('#advance-search-result').addClass('hidden');
    $("#advance-search-form").removeClass('hidden');
    $("#view-search-param").addClass('hidden');
    $("#back-to-search").addClass('hidden');
});

$("#view-search-param").click(function () {
    $("#advance-search-form").removeClass('hidden');
    $(".title-result").addClass('hidden');
    $("#view-search-param").addClass('hidden');
});

var dynamicForm = '<div class="dynamic-search-param row"><div class="row"><a class="close-button-div icon fw fw-error">' +
                  '</a></div><div class="form-group wr-input-control col-md-2"><label class="wr-input-label ">State</label>' +
                  '<select class="state no-tag form-control select2-custom"><option>AND</option><option>OR</option></select></div><div ' +
                  'class="form-group wr-input-control col-md-4"><label class="wr-input-label ">Key</label><select class=' +
                  '"txt-key form-control select2-custom"><option value = "deviceModel">Device Model' +
<<<<<<< HEAD
                  '</option><option value = "vendor">Vendor</option><option value = "osVersion">OS Version' +
                  '</option><option value = "batteryLevel">Battery Level</option><option value =' +
                  ' "internalTotalMemory">Internal Total Memory</option> <option value ="internalAvailableMemory">' +
                  'Internal Available Memory</option> <option value = "externalTotalMemory">externalTotalMemory</option>' +
=======
                  '</option><option value = "PhoneNumber">Phone Number</option><option value = "vendor">Vendor</option><option value = "osVersion">OS Version' +
                  '</option><option value = "batteryLevel">Battery Level</option><option value =' +
                  ' "internalTotalMemory">Internal Total Memory</option> <option value ="internalAvailableMemory">' +
                  'Internal Available Memory</option> <option value = "externalTotalMemory">External Total Memory</option>' +
>>>>>>> 964eae6f92d87baed3557b4f72bebe4bd5b4d832
                  ' <option value = "externalAvailableMemory">External Available Memory' +
                  '</option> <option value = "connectionType">Connection Type</option> <option value =' +
                  ' "ssid">SSID</option><option value = "cpuUsage">CPU Usage</option><option value = "totalRAMMemory">' +
                  'Total RAM Memory</option> <option value = "availableRAMMemory">Available RAM Memory</option>' +
                  '<option value = "pluggedIn">Plugged In</option></select></div>' +
                  '<div class="form-group wr-input-control col-md-2">' +
                  '<label class="wr-input-label ">Operator</label><select id = "operators" class="form-control' +
                  ' select2-custom no-tag operator"><option>=</option><option> !=</option><option> %</option>' +
                  '</select></div><div class="form-group ' + 'wr-input-control col-md-4"><label class="wr-input-label">Value</label>' +
                  '<input type="text" class="form-control txt-value"/></div></div>';

var nonNumericKeyValuePair = ["deviceModel", "vendor", "osVersion", "connectionType", "ssid", "pluggedIn"];

$(document).ready(function () {
    var isInit = true;
    $("#add-custom-param").click(function () {
        $("#customSearchParam").prepend(dynamicForm);
        $(".close-button-div").unbind("click");
        $(".close-button-div").bind("click", removeCustomParam);
        $(".no-tag").select2({tags: false});
        $(".txt-key").select2({tags: true}).on('change', function() {
            // Based on the selected key, relevant operations are changed
            var operationsForSelectedKey = getOperators($(this).val());
            $("#operators").empty();
            $("#operators").append(operationsForSelectedKey);
            $("#operators").select2("val", "=");
        });
    });

    /** Function to get operators based on the key Value
     *
     * @param keyValue
     */
    function getOperators(keyValue) {
        if (nonNumericKeyValuePair.indexOf(keyValue) < 0) {
<<<<<<< HEAD
            return '<option> =</option><option> !=</option><option> <</option><option> =<</option><option>' +
=======
            return '<option> =</option><option> !=</option><option> <</option><option> <=</option><option>' +
>>>>>>> 964eae6f92d87baed3557b4f72bebe4bd5b4d832
                ' ></option><option> >=</option>';
        } else {
            return '<option> =</option><option> !=</option><option><option> %</option>';
        }
    }

    /** To validate the key and value before sending that to back-end
     *
     * @param key Key of the search
     * @param value value given for the search
     */
    function isValidKeyAndValue(key, value) {
        if (nonNumericKeyValuePair.indexOf(key) < 0) {
            if (!isNaN(parseFloat(value)) && isFinite(value)){
                return true;
            }
        } else {
            return true;
        }
    }

    $("#device-search-btn").click(function () {
        var location = $("#location").val();
        var payload_obj = {};
        var conditions = [];
        var hasError = false;
        if (location) {
            var conditionObject = {};
            conditionObject.key = "LOCATION";
            conditionObject.value = location;
            conditionObject.operator = "=";
            conditionObject.state = "OR";
            conditions.push(conditionObject)
        }

        $("#customSearchParam .dynamic-search-param").each(function () {
            var value = $(this).find(".txt-value").val();
            var key = $(this).find(".txt-key").val();
            if (!hasError && value && key ) {
                if (isValidKeyAndValue(key, value)) {
                    var conditionObject = {};
                    conditionObject.key = key;
                    conditionObject.value = value;
                    conditionObject.operator = $(this).find(".operator").val();
                    conditionObject.state = $(this).find(".state").val();
                    conditions.push(conditionObject);
                } else {
                    hasError = true;
                    $("#advance-search-result").addClass("hidden");
                    $("#advance-search-form").removeClass(" hidden");
                    $('#device-listing-status').removeClass('hidden');
                    $('#device-listing-status-msg').text('Error in user input values. ' + key + " requires a" +
                        " numerical value as the search value");
                }
            }
        });

        // Sent the search conditions to back-end only, if all the values compliant with there key values
        if (hasError) {
            hasError = false;
        } else {
            payload_obj.conditions = conditions;
            var deviceSearchAPI = "/api/device-mgt/v1.0/devices/search-devices";
            $("#advance-search-form").addClass(" hidden");
            $("#loading-content").removeClass('hidden');
            var deviceListing = $("#device-listing");
            var deviceListingSrc = deviceListing.attr("src");
            $.template("device-listing", deviceListingSrc, function (template) {
                var successCallback = function (data) {
                    if (!data) {
                        $("#loading-content").addClass('hidden');
                        $("#advance-search-result").addClass("hidden");
                        $("#advance-search-form").removeClass(" hidden");
                        $('#device-listing-status').removeClass('hidden');
                        $('#device-listing-status-msg').text('No Device are available to be displayed.');
                        return;
                    }
                    data = JSON.parse(data);
                    if (data.devices.length == 0) {
                        $("#loading-content").addClass('hidden');
                        $("#advance-search-result").addClass("hidden");
                        $("#advance-search-form").removeClass(" hidden");
                        $('#device-listing-status').removeClass('hidden');
                        $('#device-listing-status-msg').text('No Device are available to be displayed.');
                        return;
                    }
                    var viewModel = {};
                    var devices = [];
                    if (data.devices.length > 0) {
                        for (i = 0; i < data.devices.length; i++) {
                            var tempDevice = data.devices[i];
                            var device = {};
                            device.type = tempDevice.type;
                            device.name = tempDevice.name;
                            device.deviceIdentifier = tempDevice.deviceIdentifier;
                            var properties = {};
                            var enrolmentInfo = {};
                            properties.VENDOR = tempDevice.deviceInfo.vendor;
                            properties.DEVICE_MODEL = tempDevice.deviceInfo.deviceModel;
                            device.enrolmentInfo = tempDevice.enrolmentInfo;
                            device.properties = properties;
                            devices.push(device);
                        }
                        viewModel.devices = devices;
                        $('#advance-search-result').removeClass('hidden');
                        $("#view-search-param").removeClass('hidden');
                        $("#back-to-search").removeClass('hidden');
                        $('#device-grid').removeClass('hidden');
                        $('#ast-container').removeClass('hidden');
                        $('#user-listing-status-msg').text("");
                        var content = template(viewModel);
                        $("#ast-container").html(content);
                    } else {
                        $('#device-listing-status').removeClass('hidden');
                        $('#device-listing-status-msg').text('No Device are available to be displayed.');
                    }
                    $("#loading-content").addClass('hidden');
                    if (isInit) {
                        $('#device-grid').datatables_extended();
                        isInit = false;
                    }
                    $(".icon .text").res_text(0.2);
                };
                invokerUtil.post(deviceSearchAPI,
                    payload_obj,
                    successCallback,
                    function (message) {
                        $("#loading-content").addClass('hidden');
                        $("#advance-search-result").addClass("hidden");
                        $("#advance-search-form").removeClass(" hidden");
                        $('#device-listing-status').removeClass('hidden');
                        $('#device-listing-status-msg').text('Server is unable to perform the search please enroll at least one device or check the search query');
                    }
                );
            });
        }
    });
});
