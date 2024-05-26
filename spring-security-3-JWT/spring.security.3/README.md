
SpringSecurity secures our application through authentication and authorization.

`UserDetailsService` --> Authentication.
`SecurityFilterChain` --> Authorization.
`UserDetails` --> To create an User.

```java

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig { }
```

We must annotate our class with `@EnableMethodSecurity` to enable the role authorization in method level.


### Authentication

```java
@Bean
  public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    UserDetails admin = User.withUsername("sai")
            .password(passwordEncoder.encode("sai"))
            .roles("ADMIN")
            .build();

    UserDetails user = User.withUsername("uj")
            .password(passwordEncoder.encode("uj"))
            .roles("USER")
            .build();

    return new InMemoryUserDetailsManager(admin, user);
  }
```

### Authorization

```java
@Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth ->
                    auth.requestMatchers("/products/welcome").permitAll()
                            .requestMatchers("/products/**")
                            .authenticated()
            )
            .httpBasic(Customizer.withDefaults()).build();
  }
  
  // All the users are able to reach the end point "/products/welcome" but not the "/products/**" because we made it authorized
  // and only authorized users will be able to access it. 
```



In Authentication step we created 2 users and only those users are able to authenticate into the application. We also gave specific roles to every user and let's see them in action.

```java
  @GetMapping("/all")
  @PreAuthorize("hasAuthority('ROLE_ADMIN')")
  public List<Product> getAllTheProducts() {
    return service.getProducts();
  }
  
  // With this step only `ADMIN` will be able to call "/all".

  // To use `@PreAuthorized()` we need `@EnableMethodSecurity` in the config class.
```

## UserInfo

We are using hardcoded users in the authentication part now, let's replace those and use an in-memory DB to fetch them.

```java
@Bean
  public UserDetailsService userDetailsService() {
    return new UserDetailsFromRepositoryService();
  }
```
In the above step we removed the whole hardcoded UserDetails and fetching from the service itself.

Let's see how UserDetailsFromRepositoryService looks like.
```java
@Component
public class UserDetailsFromRepositoryService implements UserDetailsService {

  @Autowired
  private UserInfoRepository userInfoRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    Optional<UserInfo> userInfo = userInfoRepository.findByName(username);

    return userInfo.map(detail -> new ConvertUserInfoToUserDetails(detail))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }
}
```

The reason we are implementing `UserDetailsService` is, the authentication bean created accepts only of type `UserDetailsService`.

Fetched userInfo from the repo must be converted to `UserDetails`. Take a look at `ConvertUserInfoToUserDetails` class 
for the way we converted UserInfo fetched from db to UserDetails.