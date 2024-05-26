package com.spring.security3.service;

import com.spring.security3.config.ConvertUserInfoToUserDetails;
import com.spring.security3.entity.UserInfo;
import com.spring.security3.repository.UserInfoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UserInfoUserDetailsService implements UserDetailsService {

  @Autowired
  private UserInfoRepository repository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    Optional<UserInfo> userInfo = repository.findByName(username);
    return userInfo.map(ConvertUserInfoToUserDetails::new)
            .orElseThrow(() -> new UsernameNotFoundException("user not found " + username));

  }
}
