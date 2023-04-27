package com.gaurav.authorizationserver.repository;

import com.gaurav.authorizationserver.model.UserRole;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<UserRole, Long>
{
    @Query("SELECT user from UserRole user where user.email_id = ?1")
    UserRole findByEmail_id(String email_id);
}
