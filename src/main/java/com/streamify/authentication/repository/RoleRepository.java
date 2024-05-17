package com.streamify.authentication.repository;

import com.streamify.authentication.models.ERole;
import com.streamify.authentication.models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface RoleRepository extends MongoRepository<Role, String> {
    Optional<Role> findByName(ERole name);
}
