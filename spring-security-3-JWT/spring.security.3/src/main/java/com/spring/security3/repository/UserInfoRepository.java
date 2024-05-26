package com.spring.security3.repository;

import com.spring.security3.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfo, Integer> {
  Optional<UserInfo> findByName(String username);

}