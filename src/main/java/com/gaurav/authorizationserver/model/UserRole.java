package com.gaurav.authorizationserver.model;

import javax.persistence.*;
import java.util.Date;
import java.util.Objects;

@Entity
@Table(name ="UserRole")
public class UserRole
{
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name="user_id", nullable = false, length = 3)
    private Long user_id;

    private String user_name;

    private String email_id;

    private Long phone_number;
    private String password;
    private String role;
    private Date date_added;

    public UserRole() {
    }
    public UserRole(String email_id, String password) {
        this.email_id = email_id;
        this.password = password;
    }

    public UserRole(String user_name, String email_id, Long phone_number, String password, String role,Date date_added) {
        this.user_name = user_name;
        this.email_id = email_id;
        this.phone_number = phone_number;
        this.password = password;
        this.role = role;
        this.date_added = date_added;
    }

    public Long getUser_id() {
        return user_id;
    }

    public void setUser_id(Long user_id) {
        this.user_id = user_id;
    }

    public String getUser_name() {
        return user_name;
    }

    public void setUser_name(String user_name) {
        this.user_name = user_name;
    }

    public String getEmail_id() {
        return email_id;
    }

    public void setEmail_id(String email_id) {
        this.email_id = email_id;
    }

    public Long getPhone_number() {
        return phone_number;
    }

    public void setPhone_number(Long phone_number) {
        this.phone_number = phone_number;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
    public Date getDate_added() {
        return date_added;
    }

    public void setDate_added(Date date_added) {
        this.date_added = date_added;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserRole userRole = (UserRole) o;
        return Objects.equals(user_id, userRole.user_id) && Objects.equals(user_name, userRole.user_name) && Objects.equals(email_id, userRole.email_id) && Objects.equals(phone_number, userRole.phone_number) && Objects.equals(password, userRole.password) && Objects.equals(date_added, userRole.date_added);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user_id, user_name, email_id, phone_number, password, date_added);
    }

    @Override
    public String toString() {
        return "UserRole{" +
                "user_id=" + user_id +
                ", user_name='" + user_name + '\'' +
                ", email_id='" + email_id + '\'' +
                ", phone_number=" + phone_number +
                ", password='" + password + '\'' +
                ", date_added=" + date_added +
                '}';
    }
}
