package com.gaurav.authorizationserver.controller.util;
public class RestResponseStatus
{
    private String status;
    private String message;

    public RestResponseStatus() {
    }

    public RestResponseStatus(String status, String message) {
        this.status = status;
        this.message = message;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
