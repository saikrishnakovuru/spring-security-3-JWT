package com.spring.security3.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.spring.security3.dto.AuthenticationRequestDetails;
import com.spring.security3.dto.Product;
import com.spring.security3.entity.UserInfo;
import com.spring.security3.service.JwtTokenGeneratingService;
import com.spring.security3.service.ProductService;

@RestController
@RequestMapping("/products")
public class ProductController {

  @Autowired
  private ProductService service;
  @Autowired
  private JwtTokenGeneratingService jwtService;
  @Autowired
  private AuthenticationManager authenticationManager;

  @GetMapping("/welcome")
  public String welcome() {
    return "Welcome this endpoint is not secure";
  }

  @PostMapping("/new")
  public String addNewUser(@RequestBody UserInfo userInfo) {
    return service.addUser(userInfo);
  }

  @GetMapping("/all")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public List<Product> getAllTheProducts() {
    return service.getProducts();
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasAuthority('ROLE_USER')")
  public Product getProductById(@PathVariable int id) {
    return service.getProduct(id);
  }

  @PostMapping("/authenticate")
  public String authenticateAndGetTken(@RequestBody AuthenticationRequestDetails details) {
    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(details.getUsername(), details.getPassword()));
    if (authentication.isAuthenticated())
      return jwtService.generateToken(details.getUsername());
    else
      throw new UsernameNotFoundException("invalid user request !");

  }

}