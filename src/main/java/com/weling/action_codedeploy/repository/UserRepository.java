package com.weling.action_codedeploy.repository;


import com.weling.action_codedeploy.dto.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByKakaoId(Long kakaoId);

    Optional<User> findByEmail(String email);
}